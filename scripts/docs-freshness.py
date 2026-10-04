#!/usr/bin/env python3
"""docs-freshness.py — is the published documentation site as new as main?

A deploy can stop without anything failing. On 2026-09-30 the deploy job of
docs.yml run 36765144410 went into `waiting` on the github-pages environment —
which requires no reviewer and sets no wait timer, so nothing configured should
have held it — and stayed there for days. A waiting job is not a failed job:
no check turned red. It held the deploy concurrency group, so every later docs
run queued behind it and was cancelled by the next push, and the live site kept
serving its Sep 29 build while new guides answered 404.

That failure has no commit, so no check of a diff can see it. The site itself
can: scripts/build-docs.py stamps every build with the commit it was built from
(`build.json` at the site root), and this script compares the stamp with main:

  * which docs-touching commits main has that the site does not — "docs-
    touching" meaning a path in docs.yml's own `on.push.paths`, exactly the
    pushes that are supposed to publish;
  * since when: the moment the first of them reached main, read off the
    docs.yml run its push created (its commit date when no run is on record);
  * every docs.yml run on the branch that has not finished — a deploy waiting
    on its environment, one pending behind another — and since when.

It fails (exit 1) when the site lags main by more than --max-lag-hours (six by
default) or carries no usable stamp, and names the runs to act on. Exit 2 means
the check itself could not run: no history to compare with, no docs.yml.

    make docs-freshness                      # what the scheduled workflow runs
    python3 scripts/docs-freshness.py --max-lag-hours 1

It reads git history (fetching the branch from origin first, unless
--no-fetch), the live site, and the GitHub REST API, authenticated by
$GITHUB_TOKEN or $GH_TOKEN when either is set. Unauthenticated it spends a
handful of the 60 requests an hour GitHub allows. The API only explains; the
verdict needs just git and the site, so an API failure is reported, not fatal.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The workflow that publishes the site, read from the branch being checked.
WORKFLOW_PATH = ".github/workflows/docs.yml"
WORKFLOW_FILE = os.path.basename(WORKFLOW_PATH)
# site_url and repo_url default from here, read from the same branch.
MKDOCS_PATH = "website/mkdocs.yml"
# scripts/build-docs.py STAMP_NAME: published at the site root.
STAMP_NAME = "build.json"
# The environment docs.yml's deploy job names.
PAGES_ENVIRONMENT = "github-pages"

API_URL = "https://api.github.com"
DEFAULT_MAX_LAG_HOURS = 6.0
UNFINISHED = {"requested", "queued", "pending", "waiting", "in_progress"}

EXIT_OK, EXIT_STALE, EXIT_ERROR = 0, 1, 2


class CheckError(Exception):
    """The check cannot run at all — exit 2, which is not a verdict on the site."""


class ApiError(Exception):
    """A GitHub API request failed. Diagnostics only: reported, never fatal."""


class Commit(NamedTuple):
    sha: str
    time: dt.datetime
    subject: str


# ------------------------------------------------------------------- time

def parse_time(value: str) -> dt.datetime:
    # fromisoformat accepts a trailing Z only from Python 3.11.
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)


def at(moment: dt.datetime) -> str:
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def span(delta: dt.timedelta) -> str:
    seconds = max(0, int(delta.total_seconds()))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m"


# ------------------------------------------------------- docs.yml triggers

KEY_RE = re.compile(r'^(?P<key>"[^"]*"|\'[^\']*\'|[A-Za-z_][\w.-]*)\s*:(?:\s+(?P<value>.*))?$')


def unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def strip_comment(line: str) -> str:
    """The line without a trailing `# comment`; a '#' inside quotes is kept."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line.rstrip()


def push_paths(workflow: str) -> list[str]:
    """The globs of a workflow's `on: push: paths:`.

    A line scanner rather than a YAML parser: PyYAML is not in the standard
    library, and it reads the key `on` as the boolean true besides. It knows the
    shape docs.yml has — block mappings, a block or flow list of scalar globs,
    comments anywhere — and refuses anything it cannot read rather than guess,
    because a wrong list here silently changes what "stale" means.
    tests/docs/docs_freshness_test.go holds it to a real YAML parser.
    """
    stack: list[tuple[int, str]] = []
    globs: list[str] = []
    seen = False
    for raw in workflow.splitlines():
        line = strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()
        if text == "-" or text.startswith("- "):
            # A block sequence may sit at its key's own indentation.
            while stack and stack[-1][0] > indent:
                stack.pop()
            if [key for _, key in stack] == ["on", "push", "paths"]:
                globs.append(unquote(text[1:]))
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        match = KEY_RE.match(text)
        if not match:
            continue
        key, value = unquote(match.group("key")), (match.group("value") or "").strip()
        if [k for _, k in stack] + [key] == ["on", "push", "paths"]:
            seen = True
            if value:
                if not (value.startswith("[") and value.endswith("]")):
                    raise CheckError(f"{WORKFLOW_PATH}: on.push.paths is neither a block "
                                     f"nor a flow list: {value!r}")
                globs.extend(unquote(item) for item in value[1:-1].split(",") if item.strip())
        if not value:
            stack.append((indent, key))
    if not seen or not globs:
        raise CheckError(f"{WORKFLOW_PATH} has no on.push.paths list, so nothing defines a "
                         "docs-touching commit — if the trigger changed shape, teach "
                         "push_paths() in scripts/docs-freshness.py the new one")
    negated = [g for g in globs if g.startswith("!")]
    if negated:
        raise CheckError(f"{WORKFLOW_PATH}: negated path patterns ({', '.join(negated)}) are "
                         "order-dependent on GitHub and have no git pathspec equivalent; "
                         "scripts/docs-freshness.py does not support them")
    return globs


def pathspecs(globs: list[str]) -> list[str]:
    # :(glob) gives `*` and `**` the meaning GitHub's path filters give them;
    # :(top) anchors them at the repository root whatever the working directory.
    return [f":(top,glob){g}" for g in globs]


def mkdocs_setting(config: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}:\s*(\S+)\s*$", config, re.M)
    return unquote(match.group(1)) if match else None


# -------------------------------------------------------------------- git

class Git:
    def __init__(self, repo_dir: str):
        self.repo_dir = repo_dir

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        try:
            done = subprocess.run(["git", "-C", self.repo_dir, *args],
                                  capture_output=True, text=True)
        except OSError as err:
            raise CheckError(f"cannot run git: {err}") from err
        if check and done.returncode != 0:
            detail = done.stderr.strip() or f"exit status {done.returncode}"
            raise CheckError(f"git {' '.join(args)}: {detail}")
        return done

    def out(self, *args: str) -> str:
        return self.run(*args).stdout.strip()

    def ok(self, *args: str) -> bool:
        return self.run(*args, check=False).returncode == 0

    def has_commit(self, sha: str) -> bool:
        return self.ok("cat-file", "-e", f"{sha}^{{commit}}")

    def contains(self, tip: str, commit: str) -> bool:
        """Whether `commit` is `tip` or one of its ancestors."""
        return self.ok("merge-base", "--is-ancestor", commit, tip)

    def commits(self, *revs: str, specs: list[str]) -> list[Commit]:
        """Commits in `revs` touching `specs`, newest first."""
        out = self.out("log", "--format=%H%x1f%cI%x1f%s", *revs, "--", *specs)
        found = []
        for line in out.splitlines():
            sha, when, subject = line.split("\x1f", 2)
            found.append(Commit(sha, parse_time(when), subject))
        return found

    def commit(self, sha: str) -> Commit:
        sha, when, subject = self.out("show", "-s", "--format=%H%x1f%cI%x1f%s",
                                      sha).split("\x1f", 2)
        return Commit(sha, parse_time(when), subject)


# ------------------------------------------------------------------- HTTP

def http(url: str, method: str = "GET", headers: dict | None = None,
         attempts: int = 3) -> tuple[int, dict, bytes]:
    """(status, headers, body). Connection errors and 5xx are retried: a
    scheduled check that turns red on one dropped packet teaches people to
    ignore it."""
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as err:
            if err.code < 500 or attempt == attempts:
                return err.code, dict(err.headers or {}), err.read()
        except OSError:                     # URLError, timeouts, resets
            if attempt == attempts:
                raise
        time.sleep(2 * attempt)
    raise AssertionError("unreachable")


def header(headers: dict, name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


class GitHub:
    def __init__(self, api_url: str, repo: str, token: str | None):
        self.api_url = api_url.rstrip("/")
        self.repo = repo
        self.token = token

    def get(self, path: str, **params) -> object:
        url = f"{self.api_url}/repos/{self.repo}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "cloop-docs-freshness"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            status, response_headers, body = http(url, headers=headers)
        except OSError as err:
            raise ApiError(f"GET {path}: {err}") from err
        if status != 200:
            if status in (403, 429) and header(response_headers, "X-RateLimit-Remaining") == "0":
                raise ApiError(f"GET {path}: rate limited — set GITHUB_TOKEN to raise the limit")
            try:
                message = json.loads(body).get("message", "")
            except (ValueError, AttributeError):
                message = ""
            raise ApiError(f"GET {path}: HTTP {status} {message}".rstrip())
        return json.loads(body)

    # docs.yml runs on the branch: the newest hundred, plus any held ones
    # older than that — a hold is exactly what outlives a page of history.
    def runs(self, branch: str) -> list[dict]:
        found: dict[int, dict] = {}
        for status in (None, "waiting", "pending"):
            params = {"branch": branch, "per_page": 100}
            if status:
                params["status"] = status
            listing = self.get(f"/actions/workflows/{WORKFLOW_FILE}/runs", **params)
            for run in listing.get("workflow_runs", []):
                found[run["id"]] = run
        return sorted(found.values(), key=lambda run: run["created_at"])

    def unfinished_jobs(self, run_id: int) -> list[dict]:
        jobs = self.get(f"/actions/runs/{run_id}/jobs", per_page=100).get("jobs", [])
        return [job for job in jobs if job.get("status") != "completed"]

    def pending_deployments(self, run_id: int) -> list[dict]:
        return self.get(f"/actions/runs/{run_id}/pending_deployments")

    def last_pages_deployment(self) -> tuple[str, dt.datetime] | None:
        """(sha, when) of the newest github-pages deployment that succeeded."""
        for deployment in self.get("/deployments", environment=PAGES_ENVIRONMENT, per_page=10):
            for status in self.get(f"/deployments/{deployment['id']}/statuses", per_page=20):
                if status.get("state") == "success":
                    return deployment["sha"], parse_time(status["created_at"])
        return None


# --------------------------------------------------------------- the site

def live_stamp(site_url: str) -> tuple[dict | None, str | None]:
    """(stamp, None) or (None, why there is no usable stamp)."""
    url = urllib.parse.urljoin(site_url, STAMP_NAME)
    try:
        # The query string only defeats the CDN's ten-minute cache.
        status, _, body = http(f"{url}?t={int(time.time())}")
    except OSError as err:
        return None, f"could not fetch {url}: {err}"
    if status == 404:
        return None, (f"{url} answered 404: the site carries no build stamp, so it was "
                      "built before stamping existed, or not by scripts/build-docs.py")
    if status != 200:
        return None, f"{url} answered HTTP {status}"
    try:
        stamp = json.loads(body)
    except ValueError:
        return None, f"{url} is not JSON"
    commit = stamp.get("commit") if isinstance(stamp, dict) else None
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        return None, f"{url} names no commit (\"commit\": {json.dumps(commit)})"
    return stamp, None


def last_modified(site_url: str) -> str | None:
    try:
        status, headers, _ = http(site_url, method="HEAD")
    except OSError:
        return None
    return header(headers, "Last-Modified") if status == 200 else None


# ----------------------------------------------------------------- report

class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.failures: list[str] = []
        self.warnings: list[str] = []
        self.remedy: str | None = None

    def section(self, label: str, first: str, *more: str) -> None:
        self.lines.append(f"  {label:<12} {first}")
        self.lines.extend(f"  {'':<12} {line}" for line in more)

    def fail(self, reason: str, headline: bool = False) -> None:
        if headline:
            self.failures.insert(0, reason)
        else:
            self.failures.append(reason)

    def warn(self, reason: str) -> None:
        self.warnings.append(reason)


def landed(git: Git, commit: Commit, push_runs: list[dict]) -> tuple[dt.datetime, str]:
    """When `commit` reached the branch, and how that is known.

    The push that delivered it created a docs.yml run whose head contains it;
    the earliest such run's creation is the push. A commit's own date can be
    much older than its push — written yesterday, pushed now — and judging by
    it would call a site stale that has had no chance to deploy yet.
    """
    for run in push_runs:
        if git.has_commit(run["head_sha"]) and git.contains(run["head_sha"], commit.sha):
            return parse_time(run["created_at"]), f"its push created docs.yml run {run['id']}"
    return commit.time, "its commit date; no docs.yml push run on record contains it"


class RunView(NamedTuple):
    run: dict
    lines: list[str]
    waiting_since: dt.datetime | None   # set when a job waits on an environment


def describe_run(gh: GitHub, run: dict, now: dt.datetime, report: Report) -> RunView:
    created = parse_time(run["created_at"])
    try:
        jobs = gh.unfinished_jobs(run["id"])
    except ApiError as err:
        report.warn(f"could not list the jobs of run {run['id']}: {err}")
        jobs = []
    title = f"{WORKFLOW_FILE} run {run['id']} for {run['head_sha'][:7]} ({run['event']})"
    if jobs:
        # Each job says since when; the run's own age would overstate a hold
        # that began after its build finished.
        lines = [f"{title}, created {at(created)}: {run['status']}"]
    else:
        # A run pending on a concurrency group has no jobs yet.
        lines = [f"{title}: {run['status']} since {at(created)} ({span(now - created)})"]
    waiting_since = created if run["status"] == "waiting" else None
    for job in jobs:
        since = parse_time(job.get("created_at") or run["created_at"])
        lines.append(f"  job \"{job['name']}\": {job['status']} since {at(since)} "
                     f"({span(now - since)})")
        if job.get("status") == "waiting":
            waiting_since = since
    if waiting_since:
        try:
            deployments = gh.pending_deployments(run["id"])
        except ApiError as err:
            report.warn(f"could not read run {run['id']}'s pending deployments: {err}")
            deployments = []
        for pending in deployments:
            name = (pending.get("environment") or {}).get("name", "?")
            reviewers = len(pending.get("reviewers") or [])
            timer = pending.get("wait_timer") or 0
            if not reviewers and not timer:
                lines.append(f"  waiting on environment {name}, which requires no reviewer "
                             "and sets no wait timer: nothing configured holds it — GitHub does")
            else:
                lines.append(f"  waiting on environment {name}: {reviewers} required "
                             f"reviewer(s), wait timer {timer} min")
    lines.append(f"  {run['html_url']}")
    return RunView(run, lines, waiting_since)


def check(args: argparse.Namespace) -> tuple[int, Report, str]:
    now = parse_time(args.now) if args.now else dt.datetime.now(dt.timezone.utc)
    max_lag = dt.timedelta(hours=args.max_lag_hours)
    git = Git(args.repo_dir)
    report = Report()

    # ---- main's history
    if not args.no_fetch:
        git.run("fetch", "--quiet", "--no-tags", args.remote,
                f"+refs/heads/{args.branch}:refs/remotes/{args.remote}/{args.branch}")
    ref = args.ref or f"{args.remote}/{args.branch}"
    if git.out("rev-parse", "--is-shallow-repository") == "true":
        raise CheckError("this clone is shallow, and the check walks the branch back to the "
                         "commit the site was built from — fetch it in full "
                         "(git fetch --unshallow; in Actions, checkout with fetch-depth: 0)")
    if not git.ok("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"):
        raise CheckError(f"{ref} does not name a commit"
                         + ("" if args.no_fetch else " even after fetching it"))
    tip = git.out("rev-parse", f"{ref}^{{commit}}")
    workflow = git.run("show", f"{tip}:{WORKFLOW_PATH}", check=False)
    if workflow.returncode != 0:
        raise CheckError(f"{ref} has no {WORKFLOW_PATH}, so nothing publishes the site")
    specs = pathspecs(push_paths(workflow.stdout))
    newest = next(iter(git.commits("-1", tip, specs=specs)), None)

    mkdocs = git.run("show", f"{tip}:{MKDOCS_PATH}", check=False).stdout
    site_url = args.site_url or mkdocs_setting(mkdocs, "site_url")
    if not site_url:
        raise CheckError(f"no --site-url, and {MKDOCS_PATH} on {ref} sets no site_url")
    site_url = site_url.rstrip("/") + "/"
    repo = args.repo or os.environ.get("GITHUB_REPOSITORY") or ""
    if not repo:
        repo_url = mkdocs_setting(mkdocs, "repo_url") or ""
        repo = re.sub(r"^https://github\.com/|\.git$|/$", "", repo_url)
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise CheckError(f"cannot tell which GitHub repository publishes the site "
                         f"(got {repo!r}); pass --repo owner/name")
    gh = GitHub(args.api_url, repo, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))

    # ---- the live site
    stamp, missing = live_stamp(site_url)
    modified = last_modified(site_url)

    # ---- GitHub's view: runs on the branch, oldest first
    try:
        runs = gh.runs(args.branch)
    except ApiError as err:
        report.warn(f"could not list {WORKFLOW_FILE} runs: {err}")
        runs = []
    push_runs = [run for run in runs if run.get("event") == "push"]
    unfinished = [run for run in runs if run.get("status") in UNFINISHED]
    finished = [run for run in runs if run.get("status") == "completed"]

    # ---- what the site was built from
    base: str | None = None
    if stamp:
        base = stamp["commit"]
        built = f"built from {base[:7]}"
        if stamp.get("commit_time"):
            built += f" (committed {at(parse_time(stamp['commit_time']))})"
        if stamp.get("built_at"):
            built += f" at {at(parse_time(stamp['built_at']))}"
        detail = [stamp["run"]] if stamp.get("run") else []
        if stamp.get("dirty"):
            detail.append("from a working tree with local changes: not exactly that commit")
            report.warn(f"the live site was built from a modified working tree of {base[:7]}")
        if modified:
            detail.append(f"Last-Modified: {modified}")
        report.section("live site", built, *detail)
    else:
        report.fail(f"cannot verify the live site: {missing}")
        detail = [f"Last-Modified: {modified}"] if modified else []
        try:
            deployed = gh.last_pages_deployment()
        except ApiError as err:
            deployed = None
            detail.append(f"(the last {PAGES_ENVIRONMENT} deployment is unknown too: {err})")
        if deployed:
            base = deployed[0]
            detail.append(f"GitHub's last successful {PAGES_ENVIRONMENT} deployment: "
                          f"{base[:7]} at {at(deployed[1])} — judged from that below")
        report.section("live site", missing, *detail)

    if newest:
        report.section("main", f"newest docs-touching commit {newest.sha[:7]} "
                               f"({at(newest.time)}) {newest.subject}")
    else:
        report.section("main", f"no commit on {ref} touches {WORKFLOW_FILE}'s paths")

    # ---- how far behind
    lag = None
    if base and not git.has_commit(base):
        if stamp:
            report.fail(f"the live site was built from {base[:7]}, which {ref} does not "
                        "contain: main was rewritten, or the site was published from "
                        "elsewhere — re-run the Documentation site workflow on main")
        report.section("behind", f"{base[:7]} is not in {ref}'s history")
    elif base and not git.contains(tip, base):
        if stamp:
            report.fail(f"the live site was built from {base[:7]}, which is not on {ref}")
        report.section("behind", f"{base[:7]} is not on {ref}")
    elif base:
        unpublished = git.commits(tip, f"^{base}", specs=specs)
        if not unpublished:
            report.section("behind", "nothing: every docs-touching commit is published")
        else:
            oldest = unpublished[-1]
            since, how = landed(git, oldest, push_runs)
            lag = now - since
            count = (f"{len(unpublished)} docs-touching commit"
                     f"{'' if len(unpublished) == 1 else 's'} the site does not have")
            report.section("behind", count,
                           f"since {at(since)} ({span(lag)}), when {oldest.sha[:7]} reached "
                           f"main ({how})",
                           f"oldest: {oldest.sha[:7]} {oldest.subject}")
            if lag > max_lag:
                report.fail(f"the live site lags {ref} by {span(lag)} "
                            f"(allowed: {args.max_lag_hours:g}h) — {count}", headline=True)

    # ---- runs to act on
    views = [describe_run(gh, run, now, report) for run in unfinished]
    if views:
        report.section("unfinished", *[line for view in views for line in view.lines])
    elif runs:
        report.section("unfinished", f"none — no {WORKFLOW_FILE} run on {args.branch} "
                                     "is queued, pending, waiting or in progress")
    if finished:
        last = finished[-1]
        report.section("last run", f"{WORKFLOW_FILE} run {last['id']} for "
                                   f"{last['head_sha'][:7]} ({last['event']}): "
                                   f"{last.get('conclusion')} at "
                                   f"{at(parse_time(last['updated_at']))}",
                       last["html_url"])

    # ---- what to do about a failure
    if report.failures:
        held = [view for view in views if view.waiting_since]
        if held:
            # Deploys run one at a time, so the oldest waiting one holds the rest.
            first = held[0]
            report.remedy = (f"{WORKFLOW_FILE} run {first.run['id']} has been waiting since "
                             f"{at(first.waiting_since)} ({span(now - first.waiting_since)}) "
                             "and holds every later deploy: cancel it in the Actions tab "
                             f"({first.run['html_url']}, Cancel workflow), and the newest "
                             "pending deploy then publishes")
        elif not views and runs:
            report.remedy = (f"no {WORKFLOW_FILE} run is under way: run the Documentation "
                             f"site workflow on {args.branch} (Actions tab, Run workflow)")
    else:
        # Current today, stuck tomorrow: the next docs push will queue behind it.
        for view in views:
            if view.waiting_since and now - view.waiting_since > max_lag:
                report.warn(f"{WORKFLOW_FILE} run {view.run['id']} has been waiting since "
                            f"{at(view.waiting_since)}: the next docs-touching push will not "
                            f"publish until it is cancelled ({view.run['html_url']})")

    header_line = f"docs-freshness: {site_url} against {ref} ({tip[:7]}), {at(now)}"
    status = EXIT_STALE if report.failures else EXIT_OK
    return status, report, header_line


def annotation(text: str) -> str:
    """Text for a workflow command, which ends at a newline and decodes %-escapes."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def emit(status: int, report: Report, header_line: str, max_lag_hours: float) -> None:
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    body = [header_line, "", *report.lines]
    if report.warnings:
        body += ["", *[f"warning: {w}" for w in report.warnings]]
    if report.failures:
        verdict = "FAIL: " + report.failures[0]
        body += ["", verdict, *[f"  also: {reason}" for reason in report.failures[1:]]]
        if report.remedy:
            body.append(f"  to fix: {report.remedy}")
    else:
        verdict = (f"OK: the live site is no more than {max_lag_hours:g}h behind "
                   "the branch's documentation")
        body += ["", verdict]
    print("\n".join(body))

    if in_actions:
        for warning in report.warnings:
            print(f"::warning title=Documentation site::{annotation(warning)}")
        for reason in report.failures:
            print(f"::error title=Documentation site is stale::{annotation(reason)}")
        if report.remedy:
            print(f"::error title=Documentation site - what to do::{annotation(report.remedy)}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if in_actions and summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"### Documentation site freshness\n\n**{verdict}**\n\n```\n")
            fh.write("\n".join(body) + "\n```\n")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail when the published documentation site lags the branch's "
                    "docs-touching commits by more than --max-lag-hours.")
    parser.add_argument("--max-lag-hours", type=float, default=DEFAULT_MAX_LAG_HOURS,
                        help="how far behind the site may be (default %(default)g)")
    parser.add_argument("--branch", default="main", help="the publishing branch")
    parser.add_argument("--remote", default="origin", help="the remote to fetch it from")
    parser.add_argument("--ref", help="compare with this ref instead of <remote>/<branch>")
    parser.add_argument("--no-fetch", action="store_true",
                        help="use the ref as it is locally instead of fetching it first")
    parser.add_argument("--site-url", help="the published site (default: site_url of "
                                           f"{MKDOCS_PATH})")
    parser.add_argument("--repo", help="owner/name on GitHub (default: $GITHUB_REPOSITORY, "
                                       f"else repo_url of {MKDOCS_PATH})")
    parser.add_argument("--api-url", default=API_URL, help="GitHub REST API base URL")
    parser.add_argument("--repo-dir", default=ROOT, help="the git checkout to read")
    parser.add_argument("--now", help="judge as of this ISO 8601 time (for tests)")
    parser.add_argument("--list-paths", action="store_true",
                        help=f"print the on.push.paths globs of the working tree's "
                             f"{WORKFLOW_PATH} and exit")
    args = parser.parse_args(argv)
    if args.max_lag_hours <= 0:
        parser.error("--max-lag-hours must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.list_paths:
            with open(os.path.join(args.repo_dir, WORKFLOW_PATH), encoding="utf-8") as fh:
                print("\n".join(push_paths(fh.read())))
            return EXIT_OK
        status, report, header_line = check(args)
    except (CheckError, OSError) as err:
        print(f"docs-freshness: cannot check: {err}", file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("::error title=Documentation site freshness could not be checked::"
                  + annotation(str(err)))
        return EXIT_ERROR
    emit(status, report, header_line, args.max_lag_hours)
    return status


if __name__ == "__main__":
    sys.exit(main())
