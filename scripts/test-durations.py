#!/usr/bin/env python3
"""test-durations.py — how long each of a package's tests takes, slowest first.

Runs one package's tests the way CI's race step does (-race -cover
-covermode=atomic), as `go test -json`, and prints one line per top-level test:

    <seconds> <test>

slowest first, under a '#' header saying how and when it was measured. Two
uses:

  * When CI's time budget names a package (scripts/test-budget.py), this is
    the command that shows which of its tests the time went to:

        scripts/test-durations.py ./pkg/orchestrator/ | head -20

  * Its output is the duration table scripts/test-shards.py balances a
    sharded package's CI jobs with:

        scripts/test-durations.py ./pkg/ui/ > scripts/test-durations/pkg-ui.txt

A test's seconds are Go's own figure (the -json "Elapsed" of its pass, fail or
skip): the whole test including its subtests, without the time a parallel test
spends waiting for the sequential ones. Arguments after the package go to `go
test` as they are, e.g. -run to time a subset. The default -timeout is 60m, far
over CI's, so a measurement of a package near its limit still finishes.

Exit status is go test's: a table printed by a failing run says so on stderr.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLAGS = ["-race", "-cover", "-covermode=atomic", "-count=1"]


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Time a package's top-level tests the way CI's race step runs them.")
    p.add_argument("package", help="the package, as a path: ./pkg/ui/")
    p.add_argument("go_args", nargs=argparse.REMAINDER,
                   help="further go test arguments, e.g. -run '^TestFoo$'")
    p.add_argument("--go", default=os.environ.get("GO", "go"), help="the go command (default: $GO or go)")
    args = p.parse_args(argv)

    extra = args.go_args
    if not any(a == "-timeout" or a.startswith("-timeout=") for a in extra):
        extra = ["-timeout", "60m", *extra]
    cmd = [args.go, "test", *FLAGS, "-json", *extra, args.package]
    print(f"test-durations.py: {shlex.join(cmd)}", file=sys.stderr)

    elapsed: dict[str, float] = {}
    failed: list[str] = []
    started = time.monotonic()
    shown = started
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        try:
            ev = json.loads(line)
        except ValueError:
            sys.stderr.write(line)  # the go command's own output, e.g. a build error
            continue
        test = ev.get("Test") or ""
        if ev.get("Action") == "build-output":
            sys.stderr.write(ev.get("Output", ""))
        if not test or "/" in test:
            continue
        if ev.get("Action") in ("pass", "fail", "skip"):
            elapsed[test] = float(ev.get("Elapsed") or 0)
            if ev["Action"] == "fail":
                failed.append(test)
        if time.monotonic() - shown >= 60:
            shown = time.monotonic()
            print(f"test-durations.py: {len(elapsed)} tests done after {shown - started:.0f} s",
                  file=sys.stderr)
    code = proc.wait()

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    head = subprocess.run(["git", "rev-parse", "--short=8", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip() or "an unknown commit"
    print(f"# {args.package}: seconds per top-level test under go test {' '.join(FLAGS)}")
    print(f"# measured {stamp} at {head} on {os.cpu_count()} CPUs in {time.monotonic() - started:.0f} s; "
          f"{len(elapsed)} tests, {sum(elapsed.values()):.0f} s in all. Regenerate with:")
    print(f"#   scripts/test-durations.py {args.package}")
    for name in sorted(elapsed, key=lambda n: (-elapsed[n], n)):
        print(f"{elapsed[name]:.2f} {name}")
    if code != 0:
        why = f"{len(failed)} failed: {', '.join(failed[:10])}" if failed else "see above"
        print(f"test-durations.py: go test exited {code} ({why})", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
