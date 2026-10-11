#!/usr/bin/env python3
"""test-shards.py — split one Go package's tests across parallel CI jobs.

pkg/ui is one test binary, and every dashboard feature adds tests to it. Under
-race it took 1,397 s of CI's 1,800 s -timeout on 1417b88f, 1,787 s on
73de7f62, and on 8f3bc424 it ran out: "panic: test timed out after 30m0s".
Raising the timeout again only moves the cliff. Running the package in several
jobs at once, each with a share of its top-level tests, takes it off.

How a test is given to a shard
------------------------------

The tests are the package's own list, `go test -list .` — test, fuzz and example
functions, which are what -run selects (benchmarks are not run without -bench).

Tests in the duration table are handed out longest first, each to the shard
with the least time so far: longest-processing-time-first, the usual answer to
scheduling jobs of very different lengths on a few workers. A test the table
does not name — a new one — goes to the shard a stable hash of its name picks,
so adding a test never moves another, and the plan is the same in every job
that computes it: each shard job works out the whole plan and runs its part.

Each shard's tests become one -run regex anchored at both ends,
^(TestA|TestB|...)$. Unanchored, TestStop would also select TestStopAll in
another shard and run it twice.

The gate
--------

`check` asks Go, not this script, what each shard's regex selects: it lists the
package once per shard with that shard's regex (`go test -list <regex>`, Go's
own matching) and fails unless every test is selected by exactly one shard. A test
no regex selects would never run anywhere, and nothing else would notice — the
package would still say ok. Duration-table entries for tests that no longer
exist are reported, not fatal: the plan ignores them.

The duration table
------------------

scripts/test-durations/<package path, / as ->.txt, written by
scripts/test-durations.py: "<seconds> <test>" per line, '#' comments. It only
balances the shards; a stale table makes them uneven, never wrong. Refresh it
when they drift apart (the shard jobs' "ok" lines show each one's time):

    scripts/test-durations.py ./pkg/ui/ > scripts/test-durations/pkg-ui.txt

Usage
-----

    scripts/test-shards.py ./pkg/ui/ --shards 3 plan     # who runs what, est. seconds
    scripts/test-shards.py ./pkg/ui/ --shards 3 regex 2  # shard 2's -run regex
    scripts/test-shards.py ./pkg/ui/ --shards 3 check    # the gate

--go-flags are the build flags the tests run with ("-race -cover
-covermode=atomic" in CI), so listing builds the same binary the run then
finds in the build cache. Exit 1 is a failed gate; exit 2 is a usage error or a
package that does not build.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# What -run selects. Benchmarks are listed too, but run only under -bench.
RUNNABLE = re.compile(r"^(Test|Fuzz|Example)\w*$")


class UsageError(Exception):
    """A problem with how the script was called or with its inputs."""


def table_path(package: str) -> str:
    """The duration table's default path for a package path like ./pkg/ui/."""
    rel = package.strip().removeprefix("./").strip("/")
    if not rel or rel.startswith(".."):
        raise UsageError(f"{package!r} is not a package path inside the module, like ./pkg/ui/")
    return os.path.join(ROOT, "scripts", "test-durations", rel.replace("/", "-") + ".txt")


def load_table(path: str) -> dict[str, float]:
    """Read "<seconds> <test>" lines; '#' starts a comment."""
    table: dict[str, float] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as e:
        raise UsageError(f"cannot read the duration table: {e}") from e
    for n, line in enumerate(lines, 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split()
        try:
            if len(fields) != 2:
                raise ValueError
            seconds = float(fields[0])
            if seconds < 0 or seconds != seconds:  # negative, or NaN
                raise ValueError
        except ValueError:
            raise UsageError(f"{path}:{n}: want \"<seconds> <test>\", got {line!r}") from None
        name = fields[1]
        if name in table:
            raise UsageError(f"{path}:{n}: {name} is in the table twice")
        table[name] = seconds
    return table


def list_tests(go: str, go_flags: list[str], package: str, pattern: str = ".") -> list[str]:
    """The runnable tests `go test -list pattern` names, in source order."""
    cmd = [go, "test", *go_flags, "-list", pattern, package]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        # Not the whole regex: a shard's is tens of kilobytes.
        shown = cmd[:-2] + [pattern if len(pattern) < 80 else "<regex>", package]
        raise UsageError(f"{shlex.join(shown)} failed:\n{proc.stdout}{proc.stderr}")
    return [line for line in proc.stdout.splitlines() if RUNNABLE.match(line)]


def annotate(level: str, title: str, message: str) -> None:
    """Print a GitHub Actions annotation, escaped as the runner expects."""
    def esc(text: str, prop: bool) -> str:
        text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        return text.replace(":", "%3A").replace(",", "%2C") if prop else text
    print(f"::{level} title={esc(title, True)}::{esc(message, False)}")


def stable_hash(name: str) -> int:
    """A hash of a test name that is the same on every machine and run."""
    return int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:8], "big")


def assign(tests: list[str], table: dict[str, float], shards: int) -> tuple[list[list[str]], list[float]]:
    """Partition tests into shards; return each shard's tests and estimated seconds."""
    parts: list[list[str]] = [[] for _ in range(shards)]
    load = [0.0] * shards
    known = sorted((t for t in set(tests) if t in table), key=lambda t: (-table[t], t))
    for t in known:
        i = min(range(shards), key=lambda i: (load[i], i))
        parts[i].append(t)
        load[i] += table[t]
    for t in sorted(set(tests) - set(table)):
        parts[stable_hash(t) % shards].append(t)
    return [sorted(p) for p in parts], load


def regex_for(names: list[str]) -> str:
    """An anchored -run regex selecting exactly these top-level tests."""
    if not names:
        return "^$"  # selects nothing; no test is named ""
    return "^(" + "|".join(re.escape(n) for n in names) + ")$"


def plan(args: argparse.Namespace) -> tuple[list[str], dict[str, float], list[list[str]], list[float]]:
    table = load_table(args.table)
    tests = list_tests(args.go, args.go_flags, args.package)
    if not tests:
        raise UsageError(f"go test -list found no tests in {args.package}")
    parts, load = assign(tests, table, args.shards)
    return tests, table, parts, load


def cmd_regex(args: argparse.Namespace) -> int:
    if not 1 <= args.shard <= args.shards:
        raise UsageError(f"shard {args.shard} is not one of 1..{args.shards}")
    _, _, parts, _ = plan(args)
    print(regex_for(parts[args.shard - 1]))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    tests, table, parts, load = plan(args)
    print(f"{args.package}: {len(tests)} tests in {args.shards} shards")
    for i, (names, seconds) in enumerate(zip(parts, load), 1):
        unknown = sum(1 for n in names if n not in table)
        print(f"  shard {i}: {len(names)} tests, {seconds:.0f} s by the table"
              + (f", plus {unknown} it does not name" if unknown else ""))
    if args.verbose:
        for i, names in enumerate(parts, 1):
            for n in sorted(names, key=lambda n: (-table.get(n, -1), n)):
                est = f"{table[n]:9.2f}" if n in table else "        ?"
                print(f"{i}\t{est}\t{n}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    tests, table, parts, load = plan(args)
    owners: dict[str, list[int]] = {t: [] for t in tests}
    strays: dict[str, list[int]] = {}
    for i, names in enumerate(parts, 1):
        for t in list_tests(args.go, args.go_flags, args.package, regex_for(names)):
            if t in owners:
                owners[t].append(i)
            else:
                strays.setdefault(t, []).append(i)

    unrun = sorted(t for t, o in owners.items() if not o)
    twice = sorted((t, o) for t, o in owners.items() if len(o) > 1)
    if unrun:
        annotate("error", "Tests no shard runs",
                 f"{len(unrun)} of {args.package}'s tests are selected by no shard's -run regex, "
                 f"so CI would never run them: " + ", ".join(unrun[:20]) + (" …" if len(unrun) > 20 else ""))
    if twice:
        annotate("error", "Tests two shards run",
                 f"{len(twice)} of {args.package}'s tests are selected by more than one shard: "
                 + ", ".join(f"{t} (shards {'+'.join(map(str, o))})" for t, o in twice[:20]))
    if strays:
        # go test -list printed a name the full listing did not. Only Go's own
        # listing changing between two calls could cause it.
        annotate("error", "Shards select tests the package does not list", ", ".join(sorted(strays)))

    stale = sorted(set(table) - set(tests))
    if stale:
        annotate("notice", "Stale duration table",
                 f"{len(stale)} entries in {os.path.relpath(args.table, ROOT)} name tests "
                 f"{args.package} no longer has; refresh it with scripts/test-durations.py "
                 f"{args.package}: " + ", ".join(stale[:20]) + (" …" if len(stale) > 20 else ""))
    unknown = sorted(set(tests) - set(table))
    for i, (names, seconds) in enumerate(zip(parts, load), 1):
        print(f"shard {i}/{args.shards}: {len(names)} tests, {seconds:.0f} s by the duration table")
    if unknown:
        print(f"{len(unknown)} tests the table does not name, placed by hash: "
              + ", ".join(unknown[:10]) + (" …" if len(unknown) > 10 else ""))
    if unrun or twice or strays:
        return 1
    print(f"ok: each of {args.package}'s {len(tests)} tests is selected by exactly one of "
          f"{args.shards} shards")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description="Split a Go package's tests across CI shards.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Usage\n-----\n", 1)[1],
    )
    p.add_argument("package", help="the package, as a path: ./pkg/ui/")
    p.add_argument("--shards", type=int, required=True, help="how many shards")
    p.add_argument("--table", help="the duration table (default: scripts/test-durations/<package>.txt)")
    p.add_argument("--go-flags", default="", help='build flags, e.g. "-race -cover -covermode=atomic"')
    p.add_argument("--go", default=os.environ.get("GO", "go"), help="the go command (default: $GO or go)")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="fail unless every test is selected by exactly one shard")
    sp = sub.add_parser("plan", help="print each shard's size and estimated time")
    sp.add_argument("-v", "--verbose", action="store_true", help="also list every test")
    sr = sub.add_parser("regex", help="print one shard's -run regex")
    sr.add_argument("shard", type=int, help="which shard, from 1")
    args = p.parse_args(argv)

    try:
        if args.shards < 1:
            raise UsageError("--shards must be at least 1")
        args.go_flags = shlex.split(args.go_flags)
        args.table = args.table or table_path(args.package)
        return {"check": cmd_check, "plan": cmd_plan, "regex": cmd_regex}[args.command](args)
    except UsageError as e:
        print(f"test-shards.py: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
