#!/usr/bin/env bash
#
# Build one commit's edge-channel artifacts (Task 20376): the release platforms,
# stamped the way the hub's deploy stamps the same commit, renamed to carry the
# commit, plus the manifest a device verifies before it trusts any of them.
#
# .github/workflows/edge.yml runs this after CI passes on main, then signs every
# file it writes and publishes them on the "edge" prerelease. It is a script
# rather than inline YAML for the same reason scripts/build-release.sh is: so a
# developer can run exactly what CI runs, and so the asset names have one
# definition the Go side's drift test can hold against pkg/upgrade.
#
#   cloop_<commit>_<os>_<arch>.tar.gz     one per release platform
#   cloop_<commit>_manifest.v2.json       {schema: 2, commit, version, protocol,
#                                          sequence, archives: {name: sha256},
#                                          built_at, run}
#   cloop_<commit>_manifest.json          the same without the sequence, as
#                                          schema 1 (see below)
#
# The version is dev+g<first seven digits>: what pkg/version gives an
# in-checkout build and what /usr/local/bin/cloop-latest-update stamps today.
# The manifest's protocol is read from the built binary, not from the source,
# so it is what the binary will actually negotiate.
#
# The sequence (manifest schema 2, Task 20380) is the commit's first-parent
# position on main, `git rev-list --count --first-parent <commit>`, which the
# release script stamps into every binary beside the commit. It is what a
# device's root helper orders builds by: it refuses to install one whose
# sequence is lower than the installed binary's. This script requires the
# binary to report exactly the commit and sequence it counted, and writes the
# same pair into the manifest — so the signed manifest and the stamped binary
# can be held against each other on the device. built_at stays for a human; it
# orders nothing (a re-run of an old commit would be "newer" than every build).
#
# The schema-1 manifest is still written, under its old name, because it is
# the only one a device whose cloop predates sequences can read: that reader
# accepts exactly schema 1 at exactly that name. Without it every such device
# would be stranded off the channel by this change. It installs the build from
# it — its first sequenced build — and reads the schema-2 manifest from then on.
#
# Usage:
#   scripts/build-edge.sh <commit> [outdir]   build into outdir (default dist/edge)
#   scripts/build-edge.sh --list <commit>     print the asset names, build nothing

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE="$REPO_ROOT/scripts/build-release.sh"

usage() {
  echo "usage: $0 <commit> [outdir]" >&2
  echo "       $0 --list <commit>" >&2
  exit 2
}

check_commit() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]] || { echo "build-edge: $1 is not a full 40-digit commit id" >&2; exit 2; }
}

if [ "${1:-}" = "--list" ]; then
  commit="${2:-}"
  [ -n "$commit" ] || usage
  check_commit "$commit"
  "$RELEASE" --platforms | while IFS=/ read -r os arch; do
    printf 'cloop_%s_%s_%s.tar.gz\n' "$commit" "$os" "$arch"
  done
  printf 'cloop_%s_manifest.v2.json\n' "$commit"
  printf 'cloop_%s_manifest.json\n' "$commit"
  exit 0
fi

commit="${1:-}"
[ -n "$commit" ] || usage
check_commit "$commit"
OUTDIR="${2:-$REPO_ROOT/dist/edge}"
version="dev+g${commit:0:7}"

head=$(git -C "$REPO_ROOT" rev-parse HEAD)
if [ "$head" != "$commit" ]; then
  echo "build-edge: the checkout is at $head, not $commit; building one commit under another's name is the" >&2
  echo "            exact substitution the manifest exists to prevent" >&2
  exit 1
fi
if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then
  echo "build-edge: the checkout has uncommitted changes; an edge build is a build of $commit and nothing else" >&2
  exit 1
fi
# The whole history, or the count below is the number of commits fetched rather
# than the commit's place on main — and a too-small sequence would make every
# device that already runs a later build refuse this one, while a device given
# it would then refuse the correctly-counted builds after it as "older".
if [ "$(git -C "$REPO_ROOT" rev-parse --is-shallow-repository)" != "false" ]; then
  echo "build-edge: the checkout is shallow; the sequence is counted over the whole first-parent history" >&2
  exit 1
fi
sequence=$(git -C "$REPO_ROOT" rev-list --count --first-parent "$commit")

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
"$RELEASE" "$version" "$stage" >&2

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
while IFS=/ read -r os arch; do
  mv "$stage/cloop_${os}_${arch}.tar.gz" "$OUTDIR/cloop_${commit}_${os}_${arch}.tar.gz"
done < <("$RELEASE" --platforms)

# Ask the binary for this machine what it is: its version must be the stamp,
# and its protocol goes into the manifest.
goos=$(go env GOOS)
goarch=$(go env GOARCH)
probe="$stage/probe"
mkdir -p "$probe"
tar -xzf "$OUTDIR/cloop_${commit}_${goos}_${goarch}.tar.gz" -C "$probe" ./cloop
(cd "$probe" && ./cloop version --json) > "$stage/version.json"

python3 - "$OUTDIR" "$commit" "$version" "$stage/version.json" "$sequence" <<'PY'
import datetime, hashlib, json, os, sys

outdir, commit, version, probe, sequence = sys.argv[1:6]
sequence = int(sequence)
with open(probe) as f:
    reported = json.load(f)
if reported.get("version") != version:
    sys.exit(f"build-edge: the built binary reports {reported.get('version')!r}, expected {version!r} — "
             "the -X stamp did not take, and a device would refuse the build when it runs it")
protocol = reported.get("protocol")
if not isinstance(protocol, int) or protocol < 1:
    sys.exit(f"build-edge: the built binary reports protocol {protocol!r}")
# The binary's own stamp is what the device's root helper reads, and the
# manifest is what it holds that stamp against: they must say the same thing.
if reported.get("sequence") != sequence:
    sys.exit(f"build-edge: the built binary reports sequence {reported.get('sequence')!r}, but {commit} is "
             f"commit {sequence} on main's first-parent history — the -X stamp did not take, and a device "
             "could not order this build against the one it runs")
if reported.get("commit") != commit:
    sys.exit(f"build-edge: the built binary reports commit {reported.get('commit')!r}, expected {commit!r}")

archives = {}
for name in sorted(os.listdir(outdir)):
    if name.endswith(".tar.gz"):
        with open(os.path.join(outdir, name), "rb") as f:
            archives[name] = hashlib.sha256(f.read()).hexdigest()

run = ""
if os.environ.get("GITHUB_RUN_ID"):
    run = "{}/{}/actions/runs/{}".format(os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
                                         os.environ.get("GITHUB_REPOSITORY", ""), os.environ["GITHUB_RUN_ID"])
manifest = {
    "schema": 2,
    "commit": commit,
    "version": version,
    "protocol": protocol,
    "sequence": sequence,
    "archives": archives,
    "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run": run,
}
with open(os.path.join(outdir, f"cloop_{commit}_manifest.v2.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
# For devices whose cloop predates sequences: their reader accepts schema 1
# only, under the old name, and a sequence would mean nothing to it.
legacy = {k: v for k, v in manifest.items() if k != "sequence"}
legacy["schema"] = 1
with open(os.path.join(outdir, f"cloop_{commit}_manifest.json"), "w") as f:
    json.dump(legacy, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"build-edge: {version} is sequence {sequence} on main and speaks protocol v{protocol}; "
      f"{len(archives)} archives", file=sys.stderr)
PY

ls -la "$OUTDIR" >&2
