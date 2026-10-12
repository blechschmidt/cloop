#!/usr/bin/env python3
"""Print a release's notes: its section of CHANGELOG.md (Task 20421).

.github/workflows/release.yml publishes the result as the GitHub release body.
GitHub refuses a body over 125,000 characters, and refuses it at the end of the
release job — after every artifact was built and signed, with the tag already
pushed — so an over-long section would cost a release, not a paragraph. A
section over --limit is therefore cut at the last entry that fits and ends with
a link to the whole section in CHANGELOG.md at the tag; the limit leaves room
for the commit list --generate-notes appends below it.

A missing section prints nothing and exits 0, as the workflow always allowed:
failing a release over a changelog heading would throw the artifacts away.

Usage:
  scripts/release-notes.py <version> [--changelog CHANGELOG.md] [--limit N]
                           [--link URL]

<version> is the release's version without the "v": 0.0.5.
"""

import argparse
import re
import sys

# GitHub's cap on a release body, less room for the generated commit list.
DEFAULT_LIMIT = 110_000


def section(text, version):
    """The lines between "## [version]" and the next "## " heading."""
    lines = text.split("\n")
    out, found = [], False
    for line in lines:
        if not found:
            if re.match(r"^## \[" + re.escape(version) + r"\]", line):
                found = True
            continue
        if line.startswith("## "):
            break
        out.append(line)
    return "\n".join(out).strip("\n") + "\n" if found else ""


def cut(body, limit, link):
    """body when it fits; otherwise body cut before the last entry or heading
    that would cross the limit, with a pointer to the rest."""
    if len(body) <= limit:
        return body
    tail = f"\n\n…and more. This release's notes are longer than a GitHub release can hold; the rest is in [CHANGELOG.md]({link}).\n"
    room = limit - len(tail)
    # An entry starts with "- " at the margin, a subsection with "### ".
    starts = [m.start() for m in re.finditer(r"(?m)^(- |### )", body) if 0 < m.start() <= room]
    end = starts[-1] if starts else room
    return body[:end].rstrip() + tail


def main():
    ap = argparse.ArgumentParser(description="Print a release's section of CHANGELOG.md.")
    ap.add_argument("version")
    ap.add_argument("--changelog", default="CHANGELOG.md")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    ap.add_argument("--link", default="CHANGELOG.md", help="where the whole section can be read")
    args = ap.parse_args()
    version = args.version[1:] if args.version.startswith("v") else args.version
    with open(args.changelog, encoding="utf-8") as f:
        body = section(f.read(), version)
    if not body:
        return 0
    out = cut(body, args.limit, args.link)
    if out is not body:
        print(f"release-notes: the {version} section is {len(body)} characters, over {args.limit}; "
              f"published cut at {len(out)}", file=sys.stderr)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
