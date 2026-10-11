#!/usr/bin/env bash
#
# Merge Go coverage profiles into one, on stdout, and print its total to stderr.
#
#   scripts/merge-coverage.sh race.out ui-1.out ui-2.out ui-3.out > coverage.out
#
# CI's coverage report is assembled from several jobs since Task 20414: the race
# step's profile covers every package but pkg/ui, and each pkg/ui shard's
# covers all of pkg/ui's statements with counts from its own tests only. A
# block present in several profiles is one block, its counts added — what `go
# tool cover` itself does with duplicates — so the merged report reads as if
# pkg/ui had run in one binary. Every profile must have the same mode.
#
# The total is go tool cover -func's figure (statements in blocks run at least
# once, over all statements), computed here so that checking it needs no Go
# toolchain or module download.

set -euo pipefail

if [ $# -eq 0 ]; then
	echo "usage: merge-coverage.sh profile..." >&2
	exit 2
fi

awk '
	FNR == 1 {
		if ($1 != "mode:") { printf "%s: not a coverage profile\n", FILENAME > "/dev/stderr"; bad = 1; exit }
		if (mode == "") { mode = $2; print }
		else if ($2 != mode) { printf "%s: mode %s, but %s before it\n", FILENAME, $2, mode > "/dev/stderr"; bad = 1; exit }
		next
	}
	NF != 3 { printf "%s:%d: not a coverage block: %s\n", FILENAME, FNR, $0 > "/dev/stderr"; bad = 1; exit }
	{
		key = $1 " " $2
		if (!(key in count)) order[n++] = key
		count[key] += $3
	}
	END {
		if (bad) exit 2
		for (i = 0; i < n; i++) {
			key = order[i]
			c = count[key]
			if (mode == "set" && c > 1) c = 1
			print key, c
			split(key, f, " ")
			total += f[2]
			if (c > 0) covered += f[2]
		}
		printf "merged %d profiles, %d blocks: %.1f%% of %d statements covered\n",
			ARGC - 1, n, total ? 100 * covered / total : 0, total > "/dev/stderr"
	}
' "$@"
