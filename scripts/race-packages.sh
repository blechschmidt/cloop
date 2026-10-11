#!/usr/bin/env bash
#
# Print the packages the race step tests (CI's "Test with race detector and
# coverage", and `make test-unit`), one per line, the longest-running first.
#
#   scripts/race-packages.sh                     # every package: make test-unit
#   scripts/race-packages.sh --without pkg/ui    # all but pkg/ui: CI's race step
#
# --without leaves a package out for a caller that tests it some other way.
# CI's race step does that for pkg/ui, which runs in shard jobs of its own
# (scripts/test-shards.py, Task 20414); make test-unit still tests the whole
# package in one binary. A package named by --without must exist, like one in
# the slow list, so that a renamed package fails here instead of quietly
# coming back into the step it was taken out of.
#
# # Why the order matters
#
# `go test` runs up to -p test binaries at once but starts them strictly in the
# order the packages are named: each run waits for the one before it to start.
# The order `go list` gives is alphabetical, and the four packages that take
# minutes where nearly every other takes seconds — pkg/orchestrator,
# pkg/statedb, pkg/ui and tests/security — all sort late. So they started last:
# on the runner pkg/ui began around minute 13 and ran another 20, and the step
# waited on it with three of its four slots idle. Naming the long packages
# first lets each start as soon as its binary is built while the short ones
# fill the other slots around them — longest-processing-time-first, the usual
# answer to scheduling jobs of very different lengths on a few workers.
#
# # What it does not change
#
# The set is exactly what the step tested before: `go list ./...` without
# tests/e2e, which needs a built binary and runs in a step of its own. Only the
# order differs. A package named below that no longer exists fails the script
# rather than silently dropping out of the run, and every package not named is
# still tested, in go list's order, after the named ones.
#
# Keep `slow` to the packages that set the step's wall clock, roughly longest
# first; the numbers are in the commit that last changed it. One exception:
# tests/security is kept out of the first four. Its static checks type-check
# the whole module from source, a burst that takes every core for half a
# minute, and pkg/ui's first browser test starts Chrome cold in that same first
# minute; on the runner that start outlasted the drivers' bound (Task 20372).

set -euo pipefail
cd "$(dirname "$0")/.."
go=${GO:-go}

slow=(
	pkg/ui
	pkg/orchestrator
	pkg/statedb
	pkg/state
	pkg/secret
	tests/security
	pkg/executor/container
	pkg/featureops
	pkg/executor/projectseed
)

without=()
while [ $# -gt 0 ]; do
	case $1 in
	--without)
		[ $# -ge 2 ] || { echo "race-packages.sh: --without needs a package, like pkg/ui" >&2; exit 2; }
		rel=${2#./}
		without+=("${rel%/}")
		shift 2
		;;
	*)
		echo "usage: race-packages.sh [--without <package>]..." >&2
		exit 2
		;;
	esac
done

module=$("$go" list -m)
all=$("$go" list ./... | grep -v 'tests/e2e')

for rel in "${slow[@]}" "${without[@]}"; do
	if ! grep -qxF "$module/$rel" <<<"$all"; then
		echo "race-packages.sh: $module/$rel is not a package any more — update the slow list or --without" >&2
		exit 1
	fi
done
for rel in "${without[@]}"; do
	all=$(grep -vxF "$module/$rel" <<<"$all")
done

named=()
for rel in "${slow[@]}"; do
	if grep -qxF "$module/$rel" <<<"$all"; then
		named+=("$module/$rel")
	fi
done

printf '%s\n' "${named[@]}"
grep -vxF -f <(printf '%s\n' "${named[@]}") <<<"$all"
