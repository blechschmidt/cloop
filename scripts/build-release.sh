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
#   scripts/build-release.sh --platforms          print GOOS/GOARCH pairs only
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

# --platforms is for CI's cross-compile gate (.github/workflows/ci.yml), which
# builds what a release builds on every push. Before it existed a tag was the
# first thing to compile cloop for anything but linux/amd64, and v0.0.3's first
# release run died on linux/arm — 32-bit, where an int cannot hold 1<<40 — on
# a constant every CI run had compiled for weeks (Task 20344).
if [ "${1:-}" = "--platforms" ]; then
  printf '%s\n' "${PLATFORMS[@]}"
  exit 0
fi

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version> [outdir]" >&2
  echo "       $0 --list" >&2
  exit 2
fi

OUTDIR="${2:-$REPO_ROOT/dist/release}"

# The build's place on main (Task 20380): the commit it is a build of and that
# commit's first-parent position, stamped beside the version. A device's root
# helper refuses to install a build whose sequence is lower than the installed
# binary's, and the stamp is the only ordering two builds of main have — so a
# release carries its tagged commit's position, and moves between releases and
# edge builds are ordered in both directions.
#
# Counted on the checkout being built, which must be the whole history: a
# shallow clone counts only the commits it fetched, and a release stamped with
# that number would be refused as older by every device that ever ran an edge
# build. CI checks out with fetch-depth: 0 for exactly this.
if ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  echo "build-release: $REPO_ROOT is not a git checkout; a build is stamped with its place on main" >&2
  exit 1
fi
if [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository)" != "false" ]; then
  echo "build-release: $REPO_ROOT is a shallow clone, so the first-parent count of HEAD would be wrong;" >&2
  echo "               fetch the whole history (git fetch --unshallow, or fetch-depth: 0)" >&2
  exit 1
fi
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
SEQUENCE="$(git -C "$REPO_ROOT" rev-list --count --first-parent HEAD)"
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then
  echo "build-release: WARNING: the checkout has uncommitted changes, but the build is stamped as" >&2
  echo "               ${COMMIT} (sequence ${SEQUENCE}); CI builds only clean checkouts" >&2
fi

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> building cloop $VERSION (${COMMIT}, sequence ${SEQUENCE} on main) for ${#PLATFORMS[@]} platforms"

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
  # there is nothing to do, forever. The sequence and commit are stamped the
  # same way, for the same silent failure: an -X naming a symbol that does not
  # exist is ignored, and build-edge.sh and the release workflow check that the
  # binary reports both.
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    "$GO" build -trimpath \
      -ldflags "-s -w -X github.com/blechschmidt/cloop/pkg/version.Version=$VERSION -X github.com/blechschmidt/cloop/pkg/version.Sequence=$SEQUENCE -X github.com/blechschmidt/cloop/pkg/version.Commit=$COMMIT" \
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
