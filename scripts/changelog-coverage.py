#!/usr/bin/env python3
"""Fail when a feature or fix since the last release has no CHANGELOG.md entry (Task 20431).

scripts/unreleased-security-age.py fails the Released installer workflow when
an [Unreleased] Security entry has waited 14 days for a release — but it can
only age what is written. After v0.0.5, thirty commits landed, the security
fixes of Tasks 20422 to 20425 among them, and not one touched CHANGELOG.md: the
age gate read an empty section, passed every day, and would have gone on
passing while those fixes waited for a release indefinitely.

So this lists the commits since the latest release tag — main's first-parent
line and whatever a merge on it brings in — and fails when a feat, fix or perf
commit names a task, as "(Task N)" or "(Tasks N, M)" in its subject, that no
line added to CHANGELOG.md since the tag mentions. A feat, fix or perf commit
that names no task must add a CHANGELOG.md line itself. Every other type —
docs, test, ci, release and the rest — is exempt: it changes nothing a user
runs.

A mention counts only where the release will carry it: on a line in
[Unreleased], or in the section of a version newer than the tag (the release
being cut). A line added to a section already released does not count, and
neither does an entry that named the task before the tag: work that ships
again needs saying again.

The commits and the tags come from git alone — no network — and a shallow
clone, which has neither the history nor the tags, is refused.

Usage:
  scripts/changelog-coverage.py [--repo DIR] [--changelog CHANGELOG.md]
                                [--rev HEAD] [--since TAG]

Exit status: 0 when every task named has an entry, 1 when one has none, 2 on a
usage or repository error.
"""

import argparse
import bisect
import re
import subprocess
import sys

# A release tag, as pkg/version.IsRelease reads one: vMAJOR.MINOR.PATCH and an
# optional -prerelease, no build metadata.
VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?$")
# A conventional-commit subject: type, optional (scope), optional "!", colon.
SUBJECT = re.compile(r"^(?P<type>[A-Za-z]+)(?:\([^)]*\))?!?:")
CHECKED = ("feat", "fix", "perf")
# "(Task 20421)" or "(Tasks 20361, 20388)" in a subject.
SUBJECT_TASKS = re.compile(r"\(Tasks?\s+([^)]*)\)")
# "Task 20421" or "Tasks 20381, 20387 and 20389" in the changelog, where a list
# may wrap onto the next line.
CHANGELOG_TASKS = re.compile(r"\bTasks?\s+(\d+(?:(?:\s*,\s*(?:and\s+)?|\s+and\s+)\d+)*)")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
SECTION = re.compile(r"^## \[([^\]]+)\]")


class RepoError(Exception):
    pass


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RepoError(f"git {' '.join(args)}: {p.stderr.strip() or 'exit ' + str(p.returncode)}")
    return p.stdout


def semver(text):
    """The precedence key of a version without its "v", or None. A release
    ranks above its prereleases; prerelease fields compare numerically when
    numeric, which rank below alphanumeric ones."""
    m = VERSION.match(text)
    if not m:
        return None
    core = tuple(int(x) for x in m.group(1, 2, 3))
    if m.group(4) is None:
        return core, 1, ()
    return core, 0, tuple((0, int(f), "") if f.isdigit() else (1, 0, f) for f in m.group(4).split("."))


def latest_release_tag(repo, rev):
    """The highest-versioned release tag rev contains, or None."""
    best = None
    for tag in git(repo, "tag", "--merged", rev, "--list", "v*").split():
        key = semver(tag[1:])
        if key is not None and (best is None or key > best[0]):
            best = (key, tag)
    return best[1] if best else None


def commits(repo, since, rev):
    """Every commit in since..rev, newest first: (sha, subject, first_parent)."""
    first_parent = set(git(repo, "rev-list", "--first-parent", f"{since}..{rev}").split())
    out = []
    for record in git(repo, "log", "--format=%H%x1f%s%x1e", f"{since}..{rev}").split("\x1e"):
        record = record.strip("\n")
        if record:
            sha, subject = record.split("\x1f", 1)
            out.append((sha, subject, sha in first_parent))
    return out


def tasks_named(subject):
    return [int(n) for group in SUBJECT_TASKS.findall(subject) for n in re.findall(r"\d+", group)]


def added_lines(repo, since, rev, path):
    """The 1-based line numbers of path at rev that were added since since."""
    diff = git(repo, "diff", "--no-color", "--no-ext-diff", "--no-renames", "-U0", since, rev, "--", path)
    added = set()
    for line in diff.splitlines():
        m = HUNK.match(line)
        if m:
            start, count = int(m.group(1)), 1 if m.group(2) is None else int(m.group(2))
            added.update(range(start, start + count))
    return added


def open_lines(lines, since_key):
    """The 1-based lines that sit in [Unreleased] or in the section of a
    version newer than the tag."""
    out, inside = set(), False
    for n, line in enumerate(lines, 1):
        m = SECTION.match(line)
        if m:
            name = m.group(1).strip()
            if name.lower() == "unreleased":
                inside = True
            else:
                key = semver(name[1:] if name.startswith("v") else name)
                inside = key is not None and key > since_key
        if inside:
            out.add(n)
    return out


def mentions(text, added, since_key):
    """{task: line} for every task a line both added since the tag and in an
    unreleased section names."""
    lines = text.split("\n")
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    counted = added & open_lines(lines, since_key)
    found = {}
    for m in CHANGELOG_TASKS.finditer(text):
        for d in re.finditer(r"\d+", m.group(1)):
            n = bisect.bisect_right(starts, m.start(1) + d.start())
            if n in counted:
                found.setdefault(int(d.group()), n)
    return found


def adds_a_line(repo, sha, path):
    """Whether the commit itself adds a non-blank line to path."""
    diff = git(repo, "diff-tree", "--root", "--no-commit-id", "--no-color", "--no-ext-diff", "-p", "-U0", sha,
               "--", path)
    return any(line.startswith("+") and not line.startswith("+++") and line[1:].strip()
               for line in diff.splitlines())


def uncommitted(repo, rev, path):
    """Whether the working tree's copy of path differs from rev's."""
    return subprocess.run(["git", "-C", repo, "diff", "--quiet", rev, "--", path], capture_output=True).returncode == 1


def annotate(text):
    """Escapes text for a workflow command's message."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo", default=".", help="the repository to check (default: the current directory)")
    ap.add_argument("--changelog", default="CHANGELOG.md", help="the changelog's path inside the repository")
    ap.add_argument("--rev", default="HEAD", help="the commit to check up to (default: HEAD)")
    ap.add_argument("--since", help="the release tag to check from (default: the latest one --rev contains)")
    args = ap.parse_args(argv)
    path = args.changelog

    try:
        if git(args.repo, "rev-parse", "--is-shallow-repository").strip() != "false":
            print(f"::error::{args.repo} is a shallow clone: it holds neither the commits since the last release "
                  "nor its tag. Check out the whole history (fetch-depth: 0).", file=sys.stderr)
            return 2
        since = args.since or latest_release_tag(args.repo, args.rev)
        if since is None:
            print(f"::error::{args.rev} contains no release tag (vMAJOR.MINOR.PATCH), so there is no release to "
                  "list the commits since. Fetch the tags, or name one with --since.", file=sys.stderr)
            return 2
        since_key = semver(since[1:] if since.startswith("v") else since)
        if since_key is None:
            print(f"::error::{since} is not a release tag (vMAJOR.MINOR.PATCH).", file=sys.stderr)
            return 2
        listed = commits(args.repo, since, args.rev)
        try:
            text = git(args.repo, "show", f"{args.rev}:{path}")
        except RepoError:
            text = ""
        found = mentions(text, added_lines(args.repo, since, args.rev, path), since_key)
        unnamed = [(sha, subject) for sha, subject, _ in listed
                   if (m := SUBJECT.match(subject)) and m.group("type").lower() in CHECKED and not tasks_named(subject)
                   and not adds_a_line(args.repo, sha, path)]
    except RepoError as e:
        print(f"::error::{e}", file=sys.stderr)
        return 2

    named = {}  # task -> [(sha, subject)], oldest commit first
    checked = 0
    for sha, subject, _ in reversed(listed):
        m = SUBJECT.match(subject)
        if not m or m.group("type").lower() not in CHECKED:
            continue
        checked += 1
        for task in tasks_named(subject):
            named.setdefault(task, []).append((sha, subject))

    if args.rev == "HEAD" and uncommitted(args.repo, args.rev, path):
        print(f"note: {path} has changes HEAD does not hold, and they are not read: commit them first.")
    on_main = sum(1 for _, _, fp in listed if fp)
    print(f"{len(listed)} commit(s) since {since} ({on_main} on the first-parent line), {checked} of them feat, "
          f"fix or perf, naming {len(named)} task(s):")
    missing = []
    for task in sorted(named):
        shas = ", ".join(sha[:8] for sha, _ in named[task])
        if task in found:
            print(f"  ok       Task {task}  {path}:{found[task]}  ({shas})")
        else:
            print(f"  MISSING  Task {task}  ({shas})")
            missing.append(task)
    for sha, subject in unnamed:
        print(f"  MISSING  no task  {sha[:8]} {subject}")

    for task in missing:
        for sha, subject in named[task]:
            print(f"::error file={path},title=No changelog entry::"
                  + annotate(f"{sha[:8]} \"{subject}\" names Task {task}, which no line added to {path} since "
                             f"{since} mentions."))
    for sha, subject in unnamed:
        print(f"::error file={path},title=No changelog entry::"
              + annotate(f"{sha[:8]} \"{subject}\" is a feat, fix or perf commit that names no task and adds no "
                         f"line to {path}."))
    if not missing and not unnamed:
        print(f"Every task a feat, fix or perf commit since {since} names has an entry in {path}.")
        return 0
    print(f"Add an entry under ## [Unreleased] in {path} that names the task — \"(Task N)\" — under Security if it "
          "fixes a vulnerability, where scripts/unreleased-security-age.py holds it to 14 days for a release, and "
          "under Added, Changed or Fixed otherwise. A commit that changes nothing a user runs is typed docs:, "
          "test:, ci: or release: instead.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
