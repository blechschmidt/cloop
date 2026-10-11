#!/usr/bin/env python3
"""test-budget.py — fail when a test package uses too much of its -timeout.

A package that outgrows its -timeout fails as "panic: test timed out after
30m0s", in whichever run happens to be the first one over — and that red run
then costs whoever pushed it an investigation of a change that did nothing
wrong. pkg/ui got there by small steps — 1,034 s of a 20m limit on d033caa, a
30m timeout on 8f3bc424 nine days later, 1,397 to 1,787 s of 30m on the commits
since — with nothing saying it was coming. This says it, weeks early: it reads
`go test`'s per-package summary lines,

    ok  	github.com/blechschmidt/cloop/pkg/ui	1396.717s	coverage: 73.5% of statements
    FAIL	github.com/blechschmidt/cloop/pkg/ui	1803.836s

and fails when any package took more than --budget percent (60 by default) of
the --timeout it ran under, naming the package, its time, and the command that
shows which of its tests the time went to (scripts/test-durations.py). The 40%
left is room for a slow runner — the same package has run 54% longer on one
than on another — and for the weeks it takes to act.

    go test -timeout 30m ./... 2>&1 | tee test.log
    scripts/test-budget.py --timeout 30m test.log

Packages within budget are listed closest-first, so the step log always shows
the headroom. A log with no timed result at all fails: a gate that read nothing
would pass everything. Exit 1 is over budget or nothing read; exit 2 a usage
error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# go test's summary line for a package that ran: "ok" or "FAIL", the import
# path, the seconds. "(cached)" and "[build failed]" results carry no time.
RESULT = re.compile(r"^(ok|FAIL)\s+(\S+)\s+(\d+(?:\.\d+)?)s(?:\s|$)")

DURATION = re.compile(r"(\d+(?:\.\d+)?)(h|ms|m|s)")
UNIT = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}


def parse_duration(text: str) -> float:
    """Seconds in a Go duration like 30m, 1h30m or 90s."""
    parts = DURATION.findall(text)
    if not parts or "".join(n + u for n, u in parts) != text:
        raise ValueError(f"{text!r} is not a duration like 30m or 1h30m")
    seconds = sum(float(n) * UNIT[u] for n, u in parts)
    if seconds <= 0:
        raise ValueError(f"{text!r} is not a positive duration")
    return seconds


def annotate(level: str, title: str, message: str) -> None:
    """Print a GitHub Actions annotation, escaped as the runner expects."""
    def esc(text: str, prop: bool) -> str:
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return text.replace(":", "%3A").replace(",", "%2C") if prop else text
    print(f"::{level} title={esc(title, True)}::{esc(message, False)}")


def module_path() -> str:
    try:
        with open(os.path.join(ROOT, "go.mod"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("module "):
                    return line.split()[1]
    except OSError:
        pass
    return ""


def relative(pkg: str, module: str) -> str:
    """./pkg/ui/ for github.com/…/cloop/pkg/ui: what the commands take."""
    if module and pkg == module:
        return "./"
    if module and pkg.startswith(module + "/"):
        return "./" + pkg[len(module) + 1:] + "/"
    return pkg


def read_results(paths: list[str]) -> dict[str, float]:
    """Each package's seconds; a package listed twice keeps its longest run."""
    results: dict[str, float] = {}
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = RESULT.match(line)
                if m:
                    results[m.group(2)] = max(results.get(m.group(2), 0.0), float(m.group(3)))
    return results


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Fail when a package used too much of its go test -timeout.")
    p.add_argument("logs", nargs="+", metavar="LOG", help="go test output (plain, not -json)")
    p.add_argument("--timeout", required=True, help="the -timeout the packages ran under, e.g. 30m")
    p.add_argument("--budget", type=float, default=60.0, help="percent of the timeout allowed (default 60)")
    p.add_argument("--note", default="", help="appended to each failure, e.g. how this job is sharded")
    p.add_argument("--show", type=int, default=5, help="packages within budget to list (default 5)")
    args = p.parse_args(argv)

    try:
        limit = parse_duration(args.timeout)
        if not 0 < args.budget <= 100:
            raise ValueError(f"--budget {args.budget:g} is not a percentage in (0, 100]")
        results = read_results(args.logs)
    except (OSError, ValueError) as e:
        print(f"test-budget.py: {e}", file=sys.stderr)
        return 2

    if not results:
        annotate("error", "Test time budget", f"no package results in {', '.join(args.logs)}: "
                 f"there was nothing to check, which would pass anything")
        return 1

    allowed = limit * args.budget / 100
    module = module_path()
    over = []
    print(f"Test time budget: {args.budget:g}% of the {args.timeout} -timeout, {allowed:.0f} s, "
          f"per package ({len(results)} read). Closest to it:")
    ranked = sorted(results.items(), key=lambda kv: (-kv[1], kv[0]))
    for pkg, seconds in ranked:
        share = 100 * seconds / limit
        if seconds > allowed:
            over.append((pkg, seconds, share))
    for pkg, seconds in ranked[:max(args.show, len(over))]:
        print(f"  {100 * seconds / limit:5.1f}%  {seconds:8.1f} s  {relative(pkg, module)}"
              + ("  OVER BUDGET" if seconds > allowed else ""))

    for pkg, seconds, share in over:
        rel = relative(pkg, module)
        msg = (f"{rel} took {seconds:.1f} s, {share:.0f}% of its {args.timeout} -timeout; the budget is "
               f"{args.budget:g}% ({allowed:.0f} s), so it is {limit - seconds:.0f} s from failing as a "
               f"timeout. Its slowest tests: scripts/test-durations.py {rel} | head -20")
        if args.note:
            msg += ". " + args.note
        annotate("error", f"Test time budget: {rel}", msg)
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
