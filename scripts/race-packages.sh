#!/usr/bin/env bash
#
# Print the packages the race step tests (CI's "Test with race detector and
# coverage", and `make test-unit`), one per line, the longest-running first.
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

module=$("$go" list -m)
all=$("$go" list ./... | grep -v 'tests/e2e')

named=()
for rel in "${slow[@]}"; do
	pkg="$module/$rel"
	if ! grep -qxF "$pkg" <<<"$all"; then
		echo "race-packages.sh: $pkg is not a package any more — update the slow list" >&2
		exit 1
	fi
	named+=("$pkg")
done

printf '%s\n' "${named[@]}"
grep -vxF -f <(printf '%s\n' "${named[@]}") <<<"$all"
