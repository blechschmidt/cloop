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
#   cloop_<commit>_manifest.json          {schema, commit, version, protocol,
#                                          archives: {name: sha256}, built_at, run}
#
# The version is dev+g<first seven digits>: what pkg/version gives an
# in-checkout build and what /usr/local/bin/cloop-latest-update stamps today.
# The manifest's protocol is read from the built binary, not from the source,
# so it is what the binary will actually negotiate.
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

python3 - "$OUTDIR" "$commit" "$version" "$stage/version.json" <<'PY'
import datetime, hashlib, json, os, sys

outdir, commit, version, probe = sys.argv[1:5]
with open(probe) as f:
    reported = json.load(f)
if reported.get("version") != version:
    sys.exit(f"build-edge: the built binary reports {reported.get('version')!r}, expected {version!r} — "
             "the -X stamp did not take, and a device would refuse the build when it runs it")
protocol = reported.get("protocol")
if not isinstance(protocol, int) or protocol < 1:
    sys.exit(f"build-edge: the built binary reports protocol {protocol!r}")

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
    "schema": 1,
    "commit": commit,
    "version": version,
    "protocol": protocol,
    "archives": archives,
    "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run": run,
}
with open(os.path.join(outdir, f"cloop_{commit}_manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
    f.write("\n")
print(f"build-edge: {version} speaks protocol v{protocol}; {len(archives)} archives", file=sys.stderr)
PY

ls -la "$OUTDIR" >&2
