#!/usr/bin/env bash
#
# Run the security fuzz targets in CI, failing on findings and only on findings.
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
# Usage:
#   scripts/fuzz-ci.sh <target> [target...]
#
# Environment:
#   FUZZTIME   per-target budget, default 60s
#   FUZZPKG    package under test, default ./tests/security/

set -uo pipefail

FUZZTIME="${FUZZTIME:-60s}"
FUZZPKG="${FUZZPKG:-./tests/security/}"
# Where `go test` persists a reproducer, relative to the repository root.
CORPUS="${FUZZPKG#./}testdata/fuzz"

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <target> [target...]" >&2
  exit 2
fi

status=0

for target in "$@"; do
  echo "=== fuzzing $target for $FUZZTIME ==="
  log="$(mktemp)"

  go test "$FUZZPKG" -run XXX -fuzz "$target" -fuzztime "$FUZZTIME" >"$log" 2>&1
  rc=$?
  cat "$log"

  if [ "$rc" -eq 0 ]; then
    rm -f "$log"
    continue
  fi

  # A reproducer on disk is a finding, whatever else the log says.
  if grep -q 'Failing input written to' "$log"; then
    echo "::error title=$target::the fuzzer found a crashing input; the reproducer is in the fuzz-corpus artifact"
    status=1
    rm -f "$log"
    continue
  fi
  if [ -d "$CORPUS/$target" ] && [ -n "$(ls -A "$CORPUS/$target" 2>/dev/null)" ]; then
    echo "::error title=$target::a reproducer exists at $CORPUS/$target but the run did not name it; treating as a finding"
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
