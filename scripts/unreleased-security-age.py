#!/usr/bin/env python3
"""Fail when a security fix has waited too long for a release (Task 20421).

Everything outside a source build installs a release: the documented download,
the bootstrap a hub hands a new device, and release-channel agent upgrades.
A security fix merged to main reaches none of them until a release carries it,
and nothing in a pull request can notice that it is waiting — the fix is
correct, the code is green, and the release is simply not cut. v0.0.4 sat
current for two weeks while sixteen Security entries piled up under
[Unreleased], among them a network-reachable hub without sign-in and stored
XSS through a project's name.

So this reads CHANGELOG.md's [Unreleased] → Security section, takes each
entry's age from `git blame` — the oldest commit among the entry's lines, which
is when it first waited — and fails when any entry is older than --max-days.
Like the rest of .github/workflows/released-installer.yml, a failure means
"ship something": cut a release. It is not a verdict on any commit.

The blame needs the whole history: a shallow clone attributes every older line
to its boundary commit, which makes every entry look new. A shallow checkout is
refused rather than trusted.

Usage:
  scripts/unreleased-security-age.py [--changelog CHANGELOG.md] [--max-days 14]
                                     [--now EPOCH]

Exit status: 0 when nothing waits too long, 1 when something does, 2 on a usage
or repository error.
"""

import argparse
import os
import re
import subprocess
import sys
import time

DAY = 86400


def git(cwd, *args):
    return subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True, text=True).stdout


def security_section(lines):
    """Returns the 1-based line range [first, last] of the [Unreleased] Security
    section's body, or None when there is none."""
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^## \[Unreleased\]", line):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("## "):
            end = i
            break
    sec = None
    for i in range(start + 1, end):
        if re.match(r"^### Security\s*$", lines[i]):
            sec = i
            break
    if sec is None:
        return None
    sec_end = end
    for i in range(sec + 1, end):
        if lines[i].startswith("### ") or lines[i].startswith("## "):
            sec_end = i
            break
    if sec + 1 >= sec_end:
        return None
    return sec + 2, sec_end  # 1-based first body line, 1-based last line


def entries(lines, first, last):
    """Splits the section into entries: a "- " bullet at column 0 and every
    line up to the next one, trailing blank lines dropped. Yields (first,
    last, title) with 1-based line numbers."""
    current = None
    out = []
    for n in range(first, last + 1):
        line = lines[n - 1]
        if line.startswith("- "):
            if current:
                out.append(current)
            current = [n, n]
        elif current and line.strip():
            current[1] = n
    if current:
        out.append(current)
    return [(a, b, title_of(lines[a - 1:b])) for a, b in out]


def title_of(entry):
    """The entry's bold lead sentence, which may wrap over several lines, or
    the start of its text when it has none."""
    body = " ".join(line.strip() for line in entry)[2:].strip()
    m = re.match(r"\*\*(.+?)\*\*", body)
    if m:
        return m.group(1)
    first = re.split(r"(?<=\.)\s", body, maxsplit=1)[0]
    return first if len(first) <= 100 else first[:97] + "..."


def blame(cwd, path, first, last):
    """Returns {line number: (commit, committer time)} for the range, from
    `git blame --line-porcelain`. Uncommitted lines carry the zero commit and
    the time of the blame."""
    out = git(cwd, "blame", "--line-porcelain", "-L", f"{first},{last}", "--", path)
    result = {}
    commit = final = when = None
    for line in out.splitlines():
        if line.startswith("\t"):
            result[final] = (commit, when)
            continue
        m = re.match(r"^([0-9a-f]{40}) \d+ (\d+)", line)
        if m:
            commit, final, when = m.group(1), int(m.group(2)), None
        elif line.startswith("committer-time "):
            when = int(line.split()[1])
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--changelog", default="CHANGELOG.md")
    ap.add_argument("--max-days", type=int, default=14)
    ap.add_argument("--now", type=int, default=None, help="the time to measure from, in Unix seconds")
    args = ap.parse_args()
    now = args.now if args.now is not None else int(time.time())

    path = os.path.abspath(args.changelog)
    cwd = os.path.dirname(path)
    try:
        if git(cwd, "rev-parse", "--is-shallow-repository").strip() != "false":
            print(f"::error::{cwd} is a shallow clone, so git blame would date every older line by the clone's "
                  "boundary commit; check out the whole history (fetch-depth: 0)", file=sys.stderr)
            return 2
    except subprocess.CalledProcessError as e:
        print(f"::error::{cwd} is not a git checkout: {e.stderr.strip()}", file=sys.stderr)
        return 2

    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    span = security_section(lines)
    if span is None:
        print("[Unreleased] holds no Security entries: nothing is waiting for a release.")
        return 0
    found = entries(lines, *span)
    if not found:
        print("[Unreleased] holds no Security entries: nothing is waiting for a release.")
        return 0

    blamed = blame(cwd, os.path.relpath(path, cwd), span[0], span[1])
    aged = []
    for first, last, title in found:
        dated = [blamed[n] for n in range(first, last + 1) if n in blamed and lines[n - 1].strip()]
        commit, when = min(dated, key=lambda cw: cw[1])
        aged.append(((now - when) // DAY, when, commit, first, title))
    aged.sort(key=lambda a: a[1])

    print(f"[Unreleased] holds {len(aged)} Security entr{'y' if len(aged) == 1 else 'ies'}, oldest first "
          f"(limit {args.max_days} days):")
    for days, when, commit, first, title in aged:
        landed = time.strftime("%Y-%m-%d", time.gmtime(when))
        short = "uncommitted" if set(commit) == {"0"} else commit[:8]
        print(f"  {days:3d} days  {short}  {landed}  line {first}: {title}")

    overdue = [a for a in aged if a[0] > args.max_days]
    if not overdue:
        return 0
    for days, when, commit, first, title in overdue:
        landed = time.strftime("%Y-%m-%d", time.gmtime(when))
        print(f"::error file={args.changelog},line={first},title=Ship something::The [Unreleased] Security "
              f"entry \"{title}\" has waited {days} days for a release (since {commit[:8]} on {landed}), longer "
              f"than {args.max_days}. Every device, installer and release-channel upgrade still gets the release "
              f"before it.")
    print(f"Ship something: {len(overdue)} security fix(es) merged more than {args.max_days} days ago are in no "
          "release. Cut one — move [Unreleased] to a version in CHANGELOG.md, add the release to "
          "pkg/version/releases.go and tag the commit; the fix is a tag, not a code change.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
