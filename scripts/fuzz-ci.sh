#!/usr/bin/env bash
#
# Run fuzz targets in CI, failing on findings and only on findings.
#
# # Why this is not just `go test -fuzz`
#
# A fuzz run that burns its whole -fuzztime budget without finding anything is
# a PASS. Go's fuzz coordinator intermittently reports that budget expiry as a
# failure instead:
#
#     --- FAIL: FuzzRedactStringNeverEmitsACredentialBody (60.11s)
#         context deadline exceeded
#     FAIL
#
# The deadline fires (internal/fuzz/fuzz.go, `stop(ctx.Err())`) while a worker
# is mid-RPC, and the resulting error misses the `err == fuzzCtx.Err()` identity
# check that is supposed to suppress it — so a clean stop is reported as a test
# failure. It is timing-dependent: the same target passes on the next run, and
# passed in the same job seconds earlier. See golang/go#72104 and #56238.
#
# Left alone this turns the build red at random, which is worse than useless:
# a security gate that cries wolf is a security gate people learn to re-run
# until it is green, and then a real finding gets re-run away with it.
#
# # How a real finding is told apart
#
# Not by the exit code, and not by the word FAIL — the spurious failure has
# both. By the reproducer. When the fuzzer genuinely finds an input, the error
# is a `fuzzCrashError` and testing writes the input to disk so it can be
# replayed (testing/fuzz.go):
#
#     Failing input written to testdata/fuzz/<Target>/<hash>
#     To re-run:
#     go test -run=<Target>/<hash>
#
# The deadline artifact has no crash path, because there is no crashing input —
# nothing was found. So: a run that wrote a reproducer failed, a run whose only
# complaint is the deadline did not, and anything else (a build error, a panic
# in the harness, an OOM) fails too rather than being quietly tolerated.
#
# "Wrote a reproducer" is decided against a snapshot of the corpus directory
# taken immediately before the run, not against the directory being non-empty.
# A fixed crash leaves its input committed under testdata/fuzz/ on purpose —
# that is how it becomes a permanent regression seed (see CONTRIBUTING.md) — so
# "this directory has files in it" is true of every package that has ever had a
# finding fixed, and using it as the signal would report those packages as
# newly failing forever. pkg/egressbroker and pkg/secretbroker already carry
# five such seeds between them.
#
# Usage:
#   scripts/fuzz-ci.sh <target> [target...]
#   scripts/fuzz-ci.sh <pkg>:<target> [<pkg>:<target>...]
#
# A bare target name runs in $FUZZPKG. The <pkg>:<target> form names the
# package per target, which is what the parser targets need: they live in the
# five packages that own the parsers rather than in one suite.
#
# Environment:
#   FUZZTIME   per-target budget, default 60s
#   FUZZPKG    package for bare target names, default ./tests/security/
#   GO         the go command, default `go` from PATH

set -uo pipefail

FUZZTIME="${FUZZTIME:-60s}"
FUZZPKG="${FUZZPKG:-./tests/security/}"
# From PATH by default, and overridable for the same reason the Makefile's GO
# is: a developer box may keep its toolchain outside PATH, and on a runner the
# one on PATH is the version setup-go pinned from go.mod.
GO="${GO:-go}"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 [<pkg>:]<target> [[<pkg>:]<target>...]" >&2
  exit 2
fi

# corpus_dir maps a package and target to where `go test` persists a
# reproducer, relative to the repository root: ./pkg/config/ -> pkg/config.
corpus_dir() {
  local pkg="${1#./}"
  printf '%s/testdata/fuzz/%s' "${pkg%/}" "$2"
}

# corpus_snapshot lists the reproducers currently on disk for one target, one
# per line and sorted, or nothing at all when the directory does not exist.
#
# `cd | ls -A` rather than `find -printf`, which is GNU-only: this script is
# what `make fuzz` runs, so it has to work on a contributor's machine as well
# as on the runner.
corpus_snapshot() {
  [ -d "$1" ] || return 0
  (cd "$1" && ls -A) | sort
}

status=0

for spec in "$@"; do
  # Everything before the last colon is the package; no colon means $FUZZPKG.
  # Split this way round because an import path can contain a colon far more
  # plausibly than a Go identifier can.
  if [ "$spec" = "${spec##*:}" ]; then
    pkg="$FUZZPKG"
    target="$spec"
  else
    pkg="${spec%:*}"
    target="${spec##*:}"
  fi

  echo "=== fuzzing $target in $pkg for $FUZZTIME ==="

  # The target has to exist, and `go test -fuzz` is no help in establishing
  # that: when its pattern matches nothing it prints
  #
  #     testing: warning: no fuzz tests to fuzz
  #
  # and exits 0. So a target that is renamed, deleted, or misspelled in
  # FUZZ_TARGETS leaves this script green while fuzzing nothing at all — the
  # same way `go test -bench` reports ok for a benchmark that no longer
  # exists, which the Benchmarks job in ci.yml already guards against. Ask for
  # the listing instead: it names the target or it does not, so this fails
  # closed rather than on the wording of a warning.
  if ! listing="$("$GO" test "$pkg" -list "^${target}\$" 2>&1)"; then
    printf '%s\n' "$listing"
    echo "::error title=$target::$pkg does not build, so nothing was fuzzed"
    status=1
    continue
  fi
  if ! printf '%s\n' "$listing" | grep -qx "$target"; then
    echo "::error title=$target::$pkg has no fuzz target named $target — renamed," \
         "deleted, or misspelled. Nothing was fuzzed, and without this check that" \
         "would have passed."
    status=1
    continue
  fi

  log="$(mktemp)"
  corpus="$(corpus_dir "$pkg" "$target")"
  before="$(corpus_snapshot "$corpus")"

  # -run '^$' rather than a name that happens to match nothing: the unit tests
  # of these packages are not what is being measured, and an unanchored
  # pattern would eventually match one by accident.
  #
  # -fuzz is anchored for the same reason. `go test` refuses to fuzz when the
  # pattern matches more than one target, so an unanchored prefix — FuzzImport
  # against pkg/planio's YAML, JSON and TOML targets — fails the run with a
  # message about the pattern rather than fuzzing anything.
  "$GO" test "$pkg" -run '^$' -fuzz "^${target}\$" -fuzztime "$FUZZTIME" >"$log" 2>&1
  rc=$?
  cat "$log"

  if [ "$rc" -eq 0 ]; then
    rm -f "$log"
    continue
  fi

  # A reproducer written during this run is a finding, whatever else the log
  # says.
  new="$(comm -13 <(printf '%s\n' "$before") <(corpus_snapshot "$corpus"))"
  if [ -n "$new" ]; then
    echo "::error title=$target::the fuzzer found a crashing input; the reproducer is in the fuzz-corpus artifact:" \
         "$(printf '%s' "$new" | tr '\n' ' ')"
    status=1
    rm -f "$log"
    continue
  fi
  if grep -q 'Failing input written to' "$log"; then
    echo "::error title=$target::the fuzzer reported a crashing input; see the log above"
    status=1
    rm -f "$log"
    continue
  fi

  # No reproducer. Tolerate the budget-expiry artifact and nothing else.
  if grep -q 'context deadline exceeded' "$log"; then
    echo "::notice title=$target::fuzzing stopped at its ${FUZZTIME} budget and reported it as an error" \
         "(golang/go#72104); no input was found, so this is a pass"
    rm -f "$log"
    continue
  fi

  echo "::error title=$target::fuzzing failed without writing a reproducer — see the log above"
  status=1
  rm -f "$log"
done

exit "$status"
