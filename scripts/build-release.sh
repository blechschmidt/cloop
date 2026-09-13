#!/usr/bin/env bash
#
# Build the release artifacts for a tag, in the exact layout `cloop upgrade`
# expects to find on the GitHub release.
#
# That contract is not a convention this script is free to reinterpret. The
# upgrader computes the asset name it will look for from its own runtime
# GOOS/GOARCH (pkg/upgrade/upgrade.go, assetNameFor) and fails the upgrade
# outright if no asset matches:
#
#     cloop_<version-without-v>_<os>_<arch>.tar.gz
#
# and verifies the download against a GNU-style `checksums.txt` published
# beside it. Rename either and `cloop upgrade` breaks for every user at once,
# with an error that points at the release rather than at this file — so
# pkg/upgrade/release_assets_test.go runs this script in --list mode and fails
# if the two ever disagree.
#
# Usage:
#   scripts/build-release.sh <version> [outdir]   build artifacts into outdir
#   scripts/build-release.sh --list <version>     print artifact names only
#
# --list compiles nothing. It exists so the drift gate above can assert the
# naming without paying for five cross-compilations.

set -euo pipefail

# The platforms a release publishes. Adding one here is all that is needed for
# `cloop upgrade` to start working on it; the test asserts the platform this
# binary is *running* on is present, so dropping one is caught rather than
# silently turning that platform's upgrade into "no release asset found".
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
  darwin/amd64
  darwin/arm64
)

GO="${GO:-go}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# artifact_name mirrors pkg/upgrade.assetNameFor. The leading "v" is stripped
# because the upgrader strips it: the tag is v0.0.1, the asset is 0.0.1.
artifact_name() {
  local version="$1" os="$2" arch="$3"
  printf 'cloop_%s_%s_%s.tar.gz' "${version#v}" "$os" "$arch"
}

list_only=0
if [ "${1:-}" = "--list" ]; then
  list_only=1
  shift
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 [--list] <version> [outdir]" >&2
  exit 2
fi

if [ "$list_only" = "1" ]; then
  for platform in "${PLATFORMS[@]}"; do
    printf '%s\n' "$(artifact_name "$VERSION" "${platform%/*}" "${platform#*/}")"
  done
  exit 0
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

  archive="$OUTDIR/$(artifact_name "$VERSION" "$os" "$arch")"

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
