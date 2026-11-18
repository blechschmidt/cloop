#!/usr/bin/env python3
"""recorder.py — the helper behind scripts/demo/record-fixtures.sh.

The documentation site's demo (/demo/, scripts/build-demo.py) is the real
dashboard answering from website/demo/fixtures. record-fixtures.sh makes those
fixtures from a throwaway hub; this file does the parts that are easier in
Python than in a shell script:

  seed    fills the hub's admin surfaces through the hub's own HTTP API
          (executors, secrets and grants, an access request, knowledge
          sources, readers, teams, tokens, budget caps, …). The projects
          themselves are run by record-fixtures.sh.
  crawl   reads what the dashboard read (walk.js's recording), and fetches
          every other GET route the dashboard's scripts can call — the hub's
          route table (/api/openapi.json) less what no script under
          pkg/ui/assets names — for every project, task, executor and other
          thing the route takes.
  write   scrubs all of it (paths, hosts, credentials, e-mail addresses,
          times) and writes website/demo/fixtures.

Python 3.10 or later, standard library only. Nothing here talks to anything
but the hub it is given, on loopback. See scripts/demo/README.md.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import projects  # noqa: E402  (beside this file)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ASSETS = os.path.join(ROOT, "pkg", "ui", "assets")
FIXTURES = os.path.join(ROOT, "website", "demo", "fixtures")


def load_build_demo():
    """scripts/build-demo.py, for its request-key rules: one definition of
    which query parameters a fixture key ignores, shared with the build and
    (through its comment) with the shim."""
    spec = importlib.util.spec_from_file_location("build_demo", os.path.join(ROOT, "scripts", "build-demo.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BUILD = load_build_demo()

# Where the demo says everything lives. The projects' directories, the home
# directory and the hub, as the fixtures show them.
DEMO_HOME = "/home/demo"
DEMO_HOST = "demo.example.com"
DEMO_URL = "https://" + DEMO_HOST
# The moment the recording's first second is moved to. Every time in the
# fixtures moves by the same amount, so the projects' histories keep their
# shape; a re-recording lands on the same date, so its diff shows what changed
# rather than when.
DEMO_START = dt.datetime(2026, 11, 16, 9, 30, 0, tzinfo=dt.timezone.utc)
# The address every browser and client of the recording is shown coming from
# (RFC 5737's documentation range).
DEMO_CLIENT_IP = "198.51.100.24"


def log(msg: str) -> None:
    print("recorder: " + msg, file=sys.stderr, flush=True)


# ─────────────────────────────────────────────────────────────── the hub's API

class Hub:
    """The throwaway hub, through its HTTP API, as a script calls it: the
    static token as a bearer, JSON bodies, no Origin (a client that sends
    neither Origin nor Sec-Fetch-Site is not a page, and the origin guard lets
    it through)."""

    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, body=None, ok=(200, 201, 202, 204), raw=False, headers=None,
             token: str | None = None, timeout: float = 60):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        req = urllib.request.Request(self.url + path, data=data, method=method)
        tok = self.token if token is None else token
        if tok:
            req.add_header("Authorization", "Bearer " + tok)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, ctype, payload = resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as err:
            status, ctype, payload = err.code, err.headers.get("Content-Type", ""), err.read()
        if ok is not None and status not in ok:
            raise RuntimeError(f"{method} {path} = {status}: {payload[:600].decode('utf-8', 'replace')}")
        if raw:
            return status, ctype, payload
        if not payload:
            return {}
        try:
            return json.loads(payload)
        except ValueError:
            return {"_text": payload.decode("utf-8", "replace")}

    def get(self, path, **kw):
        return self.call("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.call("POST", path, {} if body is None else body, **kw)

    def put(self, path, body=None, **kw):
        return self.call("PUT", path, {} if body is None else body, **kw)


# ───────────────────────────────────────────────────── the dashboard's reads

WILDCARD = re.compile(r"\{[^}]*\}")


def dashboard_source() -> str:
    """The dashboard as the demo carries it — index.html, the bundle's
    fragments, the deferred panels and the page scripts index.html names —
    as tests/demo/fixtures_test.go reads it. Not the glasses or device pages."""
    import glob
    with open(os.path.join(ASSETS, "index.html"), encoding="utf-8") as fh:
        index = fh.read()
    files = [os.path.join(ASSETS, "js", "page", t) for t in re.findall(r"\{\{asset:([^}]+)\}\}", index)]
    files = [f for f in files if os.path.isfile(f)]
    files += sorted(glob.glob(os.path.join(ASSETS, "js", "*.js"))) + sorted(glob.glob(os.path.join(ASSETS, "js", "deferred", "*.js")))
    parts = [index]
    for f in files:
        with open(f, encoding="utf-8") as fh:
            parts.append(fh.read())
    return "\n".join(parts)


def referenced(src: str, pattern: str) -> bool:
    """Whether the dashboard's scripts name a route — the rule
    tests/demo/fixtures_test.go applies, so the crawl and the gate agree on
    what "a read the dashboard can make" is."""
    pieces = WILDCARD.split(pattern)
    first = re.escape(pieces[0])
    if len(pieces) == 1 and not pattern.endswith("/"):
        first += r"(?:[^A-Za-z0-9_/-]|$)"
    if not re.search(first, src):
        return False
    return all(p in src for p in pieces[1:] if p)


def dashboard_reads(hub: Hub) -> list[tuple[str, str]]:
    """(path pattern, scope) for every GET in the hub's route table that the
    dashboard names."""
    doc = hub.get("/api/openapi.json")
    src = dashboard_source()
    out = []
    for path, ops in sorted(doc.get("paths", {}).items()):
        op = ops.get("get")
        if not op or not path.startswith(("/api/", "/auth/")):
            continue
        if referenced(src, path):
            out.append((path, op.get("x-cloop-scope", "")))
    return out


# ──────────────────────────────────────────────────────────────── scrubbing

class Scrubber:
    """Everything a recording says about the machine it was made on, turned
    into the demo's invented equivalents.

    paths: real prefix -> demo prefix, applied longest first.
    secrets: exact values (tokens the recording minted) never to appear.
    hosts: real host names and addresses -> the demo's.
    start: when the recording began; every time moves by DEMO_START - start.
    """

    TS = re.compile(r"(?<![0-9])(\d{4})-(\d{2})-(\d{2})([T ])(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?(?![0-9])")
    DATE = re.compile(r"(?<![0-9-])(\d{4})-(\d{2})-(\d{2})(?![0-9T:-])")
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
    MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
    MINTED = re.compile(r"\b(cloop_[a-z0-9]+_)[A-Za-z0-9_.-]{12,}")
    LOOPBACK = re.compile(r"(?<![0-9.])127\.0\.0\.1(?![0-9])")
    HEADLESS = re.compile(r"HeadlessChrome/([0-9.]+)")
    TIME_KEY = re.compile(r"(?i)(^|_)(at|ts|time|timestamp|since|until|expires|expiry|deadline|started|ended|"
                          r"created|updated|seen|last|when|date|ms|unix)($|_)")

    def __init__(self, paths: dict[str, str], secrets: list[str], hosts: dict[str, str], start: dt.datetime,
                 window_days: int = 400, ports: dict[int, int] | None = None):
        # The hub's port, a free one picked at random, and the demo's.
        self.ports = dict(ports or {})
        # A path also travels percent-encoded, in a URL's query
        # (?project=%2Fhome%2F…), and is replaced in that form too.
        paths = dict(paths)
        for real, demo in list(paths.items()):
            paths[urllib.parse.quote(real, safe="")] = urllib.parse.quote(demo, safe="")
        self.paths = sorted(paths.items(), key=lambda kv: -len(kv[0]))
        self.secrets = sorted({s for s in secrets if s and len(s) >= 6}, key=len, reverse=True)
        self.hosts = sorted(hosts.items(), key=lambda kv: -len(kv[0]))
        self.start = start
        self.delta = DEMO_START - start
        lo, hi = start - dt.timedelta(days=window_days), start + dt.timedelta(days=window_days)
        self.window = (lo, hi)
        self.macs: dict[str, str] = {}

    # Times ---------------------------------------------------------------

    def _shift_ts(self, m: re.Match) -> str:
        y, mo, d, sep, h, mi, s, frac, zone = m.groups()
        try:
            t = dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
        except ValueError:
            return m.group(0)
        offset = dt.timedelta(0)
        if zone and zone != "Z":
            sign = 1 if zone[0] == "+" else -1
            offset = sign * dt.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        utc = (t - offset).replace(tzinfo=dt.timezone.utc)
        if not self.window[0] <= utc <= self.window[1]:
            return m.group(0)
        t2 = t + self.delta
        return f"{t2:%Y-%m-%d}{sep}{t2:%H:%M:%S}{frac or ''}{zone or ''}"

    def _shift_date(self, m: re.Match) -> str:
        try:
            d = dt.datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), 12, tzinfo=dt.timezone.utc)
        except ValueError:
            return m.group(0)
        if not self.window[0] <= d <= self.window[1]:
            return m.group(0)
        return f"{d + self.delta:%Y-%m-%d}"

    def _shift_number(self, key: str, v):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not self.TIME_KEY.search(key or ""):
            return v
        lo, hi = self.window[0].timestamp(), self.window[1].timestamp()
        secs = self.delta.total_seconds()
        if lo <= v <= hi:
            return type(v)(v + secs)
        if lo * 1000 <= v <= hi * 1000:
            return type(v)(v + secs * 1000)
        if lo * 1e9 <= v <= hi * 1e9:
            return type(v)(v + secs * 1e9)
        return v

    # Text ----------------------------------------------------------------

    def text(self, s: str) -> str:
        for secret in self.secrets:
            if secret in s:
                s = s.replace(secret, "[redacted]")
        s = self.MINTED.sub(lambda m: m.group(1) + "[redacted]", s)
        for real, demo in self.paths:
            s = s.replace(real, demo)
        for real, demo in self.hosts:
            s = s.replace(real, demo)
        for real, demo in self.ports.items():
            s = re.sub(rf"(?<=[*:]){real}(?![0-9])", str(demo), s)
        # Every client was this machine, on loopback: a documentation address
        # reads as the browser it stands for.
        s = self.LOOPBACK.sub(DEMO_CLIENT_IP, s)
        # The walk's browser is headless Chrome; what it sent before the user
        # agent was overridden still says so.
        s = self.HEADLESS.sub(r"Chrome/\1", s)
        s = self.EMAIL.sub(self._email, s)
        s = self.MAC.sub(self._mac, s)
        s = self.TS.sub(self._shift_ts, s)
        s = self.DATE.sub(self._shift_date, s)
        return s

    def _email(self, m: re.Match) -> str:
        host = m.group(1).lower()
        if host.endswith(("example.com", "example.org", "example.net")):
            return m.group(0)
        if host in ("anthropic.com", "users.noreply.github.com"):
            return m.group(0)
        return "someone@" + DEMO_HOST

    def _mac(self, m: re.Match) -> str:
        real = m.group(0).lower()
        if real not in self.macs:
            n = len(self.macs) + 1
            self.macs[real] = f"02:00:5e:00:{n >> 8:02x}:{n & 0xff:02x}"
        return self.macs[real]

    # Documents -----------------------------------------------------------

    def value(self, v, key: str = ""):
        if isinstance(v, str):
            stripped = v.strip()
            if stripped[:1] in "{[" and len(stripped) > 1:
                try:
                    inner = json.loads(v)
                except ValueError:
                    inner = None
                if isinstance(inner, (dict, list)):
                    return json.dumps(self.value(inner), separators=(",", ":"), ensure_ascii=False)
            return self.text(v)
        if isinstance(v, list):
            return [self.value(x, key) for x in v]
        if isinstance(v, dict):
            return {self.text(k): self.value(x, k) for k, x in v.items()}
        if key == "port" and isinstance(v, int) and v in self.ports:
            return self.ports[v]
        return self._shift_number(key, v)


# ──────────────────────────────────────────────────────────────── recording

def norm_key(method: str, path_qs: str) -> str:
    return BUILD.normalise(f"{method} {path_qs}", "recording")


def decode_body(raw: str | bytes | None, mime: str):
    """A JSON body as data, a text body as text, anything else as None."""
    if raw is None:
        return None, None
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None, None
    if "json" in (mime or "") or raw[:1] in "{[":
        try:
            return "json", json.loads(raw)
        except ValueError:
            pass
    if mime and not mime.startswith(("text/", "application/yaml", "application/x-yaml", "image/svg",
                                     "application/octet-stream")):
        return None, None
    return "text", raw


# Query parameters a read needs to say anything, where the crawl has to supply
# them itself (the dashboard does, from what is on the page). Keyed by route;
# {device} is the recording's edge device.
EXTRA_QUERY: dict[str, str] = {
    "/api/grants/matches": "subject=label%3Aregion%3Deu-central",
    "/api/projects/{idx}/move/preflight": "target={device}&quiesce=1",
    # The dashboard shows a text attachment in place, which is this.
    "/api/tasks/{id}/attachments/{aid}": "inline=1",
}

# Statuses other than 2xx that are a route's real answer to the dashboard,
# recorded as they are rather than reported as a crawl that went wrong.
EXPECTED_STATUS: dict[str, set[int]] = {}


def ids_in(doc, *keys: str) -> list:
    """The ids of the things a list response lists: the first list found at
    the top of the document (or the document itself), each element's first
    present key of keys."""
    keys = keys or ("id",)
    lists = []
    if isinstance(doc, list):
        lists.append(doc)
    elif isinstance(doc, dict):
        lists.extend(v for v in doc.values() if isinstance(v, list))
    out = []
    for items in lists:
        for it in items:
            if isinstance(it, dict):
                for k in keys:
                    if it.get(k) not in (None, ""):
                        out.append(it[k])
                        break
        if out:
            break
    return out


def expand(hub: Hub, pattern: str, scope: str, projects: list[dict]) -> list[tuple[str, int | None]]:
    """The concrete requests a route pattern stands for in this recording:
    (path with query, project index or None)."""
    per_project = scope == "project" or "{idx}" in pattern
    targets: list[tuple[str, int | None, str]] = []
    for p in (projects if per_project else [None]):
        idx = None if p is None else p["idx"]
        q = f"project_idx={idx}" if scope == "project" else ""
        path = pattern.replace("{idx}", str(idx)) if idx is not None else pattern
        targets.append((path, idx, q))
    out: list[tuple[str, int | None]] = []
    for path, idx, q in targets:
        pq = f"?{q}" if q else ""
        for concrete in fill_ids(hub, path, idx, pq):
            extra = EXTRA_QUERY.get(pattern, "").replace("{device}", urllib.parse.quote(DEVICE_ID[0], safe=""))
            if extra:
                concrete += ("&" if "?" in concrete else "?") + extra
            out.append((concrete, idx))
    return out


def fill_ids(hub: Hub, path: str, idx: int | None, pq: str) -> list[str]:
    """path with each remaining {wildcard} replaced by every value it takes."""
    m = WILDCARD.search(path)
    if not m:
        return [path + pq]
    head = path[:m.start()]
    values = list_for(hub, head, m.group(0), idx, pq)
    out = []
    for v in values:
        out.extend(fill_ids(hub, path[:m.start()] + urllib.parse.quote(str(v), safe="") + path[m.end():], idx, pq))
    return out


def list_for(hub: Hub, head: str, name: str, idx: int | None, pq: str) -> list:
    """Every value the wildcard after head takes: read from the list route the
    dashboard reads them from."""
    def get(path):
        try:
            return hub.get(path)
        except RuntimeError as err:
            log(f"listing {path}: {err}")
            return {}
    if head == "/api/tasks/":
        st = get("/api/state" + pq)
        return [t["id"] for t in ((st.get("plan") or {}).get("tasks") or [])]
    if head.startswith("/api/tasks/") and head.endswith("/attachments/"):
        return ids_in(get(head.rstrip("/") + pq), "id", "aid", "name")
    if head.startswith("/api/projects/") and head.endswith("/move/"):
        return ids_in(get(head.rstrip("/").rsplit("/", 1)[0] + "/moves"), "id")[:3]
    if head == "/api/requirement-runs/":
        runs = []
        for rid in ids_in(get("/api/requirements" + pq), "id"):
            for c in (get(f"/api/requirements/{rid}/checks" + pq).get("checks") or []):
                if c.get("run_id") and c["run_id"] not in runs:
                    runs.append(c["run_id"])
        return runs
    simple = {
        "/api/executors/": ("/api/executors", ("id",)),
        "/api/executor-pools/": ("/api/executor-pools", ("id",)),
        "/api/grants/": ("/api/grants", ("id",)),
        "/api/grant-requests/": ("/api/grant-requests", ("id",)),
        "/api/knowledge/sources/": ("/api/knowledge/sources", ("id",)),
        "/api/provider-calls/": ("/api/provider-calls" + pq, ("id",)),
        "/api/replay-runs/": ("/api/replay-runs" + pq, ("id",)),
        "/api/requirements/": ("/api/requirements" + pq, ("id",)),
    }
    if head in simple:
        route, keys = simple[head]
        return ids_in(get(route), *keys)
    log(f"no list for {head}{name}: not crawled")
    return []


DEVICE_ID = [""]


def crawl(hub: Hub, state: dict, args) -> int:
    DEVICE_ID[0] = state.get("device") or "local"
    # Read as Dana, whom the demo shows: the static token has no identity, so
    # a hub with single sign-on answers it differently (no Claude account, not
    # on a device's access list).
    hub = Person(hub, state["fakes"]["idp"], "dana")
    with open(args.walk, encoding="utf-8") as fh:
        walk = json.load(fh)
    projects = [{"idx": i, "path": p["path"], "name": p["name"]}
                for i, p in enumerate(hub.get("/api/projects").get("projects") or [])]
    state["projects"] = projects

    # What the dashboard itself read, keyed exactly as it asked.
    captured: dict[str, dict] = {}
    for a in walk.get("answers") or []:
        if a.get("body") is None or a.get("status") in (401, 403):
            continue
        captured[norm_key("GET", a["path"])] = {"status": a.get("status") or 200, "mime": a.get("mime") or "",
                                               "body": a["body"], "from": "dashboard"}
    seen_routes = {}
    for key in captured:
        path = key.split(" ", 1)[1].split("?", 1)[0]
        q = urllib.parse.parse_qs(key.partition("?")[2])
        seen_routes.setdefault(path, set()).add(q.get("project_idx", [None])[0])

    # Every other read the dashboard can make, fetched here.
    crawled: dict[str, dict] = {}
    misses = []
    for pattern, scope in dashboard_reads(hub):
        if scope == "stream" or pattern.startswith("/auth/") or pattern in SKIP:
            continue
        for concrete, idx in expand(hub, pattern, scope, projects):
            path = concrete.split("?", 1)[0]
            if path in seen_routes and (str(idx) if scope == "project" else None) in seen_routes[path]:
                continue
            status, ctype, payload = hub.call("GET", concrete, ok=None, raw=True)
            if not 200 <= status < 300 and status not in EXPECTED_STATUS.get(pattern, ()):
                # A 404 or 409 for one of the things a route takes is that
                # thing saying the route is not for it — a container
                # executor's virtual executors, a feature's own features —
                # and not a read the crawl got wrong.
                if not (status in (404, 409) and WILDCARD.search(pattern)) and \
                        not (pattern == "/api/projects/{idx}/features" and status == 400):
                    misses.append(f"{concrete} = {status}: {payload[:160].decode('utf-8', 'replace')}")
                continue
            # The dashboard asks with parameters of its own; this answer stands
            # for every one of them.
            wild = "?" + (f"project_idx={idx}&*" if scope == "project" else "*")
            crawled[norm_key("GET", path + wild)] = {"status": status, "mime": ctype.split(";")[0],
                                                    "body": payload.decode("utf-8", "replace"), "from": "crawl",
                                                    "asked": concrete}
    sockets = {}
    for s in walk.get("sockets") or []:
        key = norm_key("WS", s["path"])
        first = [f["data"] for f in s.get("frames") or [] if f.get("t", 0) <= 3000]
        if first and key not in sockets:
            sockets[key] = first
    out = {"captured": captured, "crawled": crawled, "sockets": sockets, "misses": misses}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    log(f"crawl: {len(captured)} read by the dashboard, {len(crawled)} fetched, {len(sockets)} sockets, "
        f"{len(misses)} misses")
    for m in misses:
        log("  miss: " + m)
    return 0


# Dashboard reads the crawl does not fetch, with the reason (the gate in
# tests/demo has the same list for the fixtures).
SKIP = {
    "/api/events": "the SSE fallback; the demo's socket never fails",
    "/api/tasks/{id}/attach": "a terminal into a running sandbox",
    "/api/projects/{idx}/repositories/available": "asks GitHub, about an App the recording made up",
    "/api/projects/{idx}/move/{id}": "the recording moves no project",
}


# ─────────────────────────────────────────────────────────────────── writing

# A query value that is a date or a Unix time.
DATED = re.compile(r"=(\d{4}-\d{2}-\d{2}|\d{10,13})(&|$)")


def group_of(key: str) -> str:
    """The file a fixture goes in: its route's first segment under /api/."""
    path = key.split(" ", 1)[1].split("?", 1)[0]
    seg = [s for s in path.split("/") if s]
    if seg[:1] == ["api"] and len(seg) > 1:
        if seg[1] == "projects" and len(seg) > 3:
            return seg[3]
        return seg[1]
    return seg[0] if seg else "root"


def project_of(key: str, projects: list[dict]) -> str | None:
    """The project a fixture belongs to, by its project_idx or {idx}."""
    path, _, query = key.split(" ", 1)[1].partition("?")
    idx = urllib.parse.parse_qs(query).get("project_idx", [None])[0]
    m = re.match(r"^/api/projects/(\d+)/", path)
    if m:
        idx = m.group(1)
    if idx is None:
        return None
    for p in projects:
        if str(p["idx"]) == str(idx):
            return p["name"]
    return None


def write(args) -> int:
    with open(args.state, encoding="utf-8") as fh:
        state = json.load(fh)
    with open(args.crawl, encoding="utf-8") as fh:
        rec = json.load(fh)
    start = dt.datetime.fromisoformat(state["started"])
    paths = dict(state.get("paths") or {})
    paths.update({"/tmp": DEMO_HOME + "/tmp", "/root": DEMO_HOME})
    ports = {int(state["hub_port"]): 8080} if state.get("hub_port") else {}
    scrub = Scrubber(paths, state.get("secrets") or [], state.get("hosts") or {}, start, ports=ports)
    projects = state.get("projects") or []

    fixtures: dict[str, dict] = {}
    skipped = []
    for source in ("crawled", "captured"):   # the dashboard's own reads win
        for key, a in rec.get(source, {}).items():
            kind, body = decode_body(a.get("body"), a.get("mime"))
            if kind is None:
                skipped.append(key)
                continue
            fx = {"request": key}
            if a.get("status", 200) != 200:
                fx["status"] = a["status"]
            if kind == "json":
                fx["body"] = scrub.value(body)
            else:
                fx["text"] = scrub.text(body)
                fx["type"] = a.get("mime") or "text/plain"
            fixtures[key] = fx
    # A read whose query carries a date the dashboard computed from the day it
    # was opened (Analytics asks from=<30 days ago>&to=<today>) matches its
    # recording only on the day it was made. Each gets a twin that answers it
    # on any day: its path and project with a wildcard for the rest.
    for key in list(fixtures):
        path, _, query = key.partition("?")
        if not query or not DATED.search(query) or path.startswith("WS "):
            continue
        idx = urllib.parse.parse_qs(query).get("project_idx", [None])[0]
        twin = norm_key(*path.split(" ", 1)) + ("?project_idx=" + idx + "&*" if idx is not None else "?*")
        twin = norm_key("GET", twin.split(" ", 1)[1])
        if twin not in fixtures:
            if "body" in fixtures[key]:
                fixtures[twin] = {"request": twin, "body": {"$fixture": key}}
            else:
                fixtures[twin] = dict(fixtures[key], request=twin)
    for key, frames in (rec.get("sockets") or {}).items():
        out = []
        for f in frames:
            try:
                doc = json.loads(f)
            except ValueError:
                out.append(scrub.text(f))
                continue
            doc = scrub.value(doc)
            out.append(link_state_frame(doc, key, fixtures))
        fixtures[key] = {"request": key, "frames": out}

    # The files, by project and by the route's first segment.
    files: dict[str, list] = {}
    for key in sorted(fixtures):
        proj = project_of(key, projects)
        name = os.path.join(proj or "hub", group_of(key) + ".json")
        files.setdefault(name, []).append(fixtures[key])
    clear_fixtures(args.out)
    total = 0
    for name, items in sorted(files.items()):
        path = os.path.join(args.out, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        total += os.path.getsize(path)
    log(f"write: {len(fixtures)} fixtures in {len(files)} files, {total // 1024} KiB, into {args.out}")
    for k in skipped:
        log("  not JSON or text, not written: " + k)
    return 0


def link_state_frame(doc, key: str, fixtures: dict):
    """A project socket's state frame says what GET /api/state says: point it
    at that fixture rather than repeat it."""
    if not (isinstance(doc, dict) and doc.get("type") == "state" and isinstance(doc.get("data"), dict)):
        return doc
    query = key.partition("?")[2]
    target = norm_key("GET", "/api/state" + (f"?{query}" if query else ""))
    fx = fixtures.get(target)
    if fx and fx.get("body") == doc["data"]:
        return {**doc, "data": {"$fixture": target}}
    return doc


def clear_fixtures(out: str) -> None:
    """Empty the fixtures directory of the JSON files and directories a
    recording writes, and nothing else."""
    if not os.path.isdir(out):
        os.makedirs(out)
        return
    for dirpath, dirnames, files in os.walk(out, topdown=False):
        for f in files:
            if f.endswith(".json"):
                os.remove(os.path.join(dirpath, f))
        if dirpath != out and not os.listdir(dirpath):
            os.rmdir(dirpath)


# ──────────────────────────────────────────────────────────────── seeding

# The people the demo shows, all invented. Dana is who the demo is recorded as:
# an administrator, and in the group of every role besides.
PEOPLE = {
    "dana": ("dana@demo.example.com", "Dana Whitfield", ["platform-admins", "maintainers", "engineers", "readers"]),
    "priya": ("priya@demo.example.com", "Priya Raman", ["engineers"]),
    "sam": ("sam@demo.example.com", "Sam Okafor", ["readers"]),
}
# The browsers their sessions are recorded as coming from.
BROWSERS = {
    "dana": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "priya": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/18.1 Safari/605.1.15",
    "sam": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 "
           "Safari/537.36 Edg/150.0.0.0",
}


class Person(Hub):
    """A person signed in to the hub through the fake identity provider: the
    hub's session cookie instead of the static token."""

    def __init__(self, hub: Hub, idp: str, who: str):
        import http.cookiejar
        super().__init__(hub.url, "")
        email, name, groups = PEOPLE[who]
        Hub(idp, "").post("/_identity", {"email": email, "name": name, "groups": groups})
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.addheaders = [("User-Agent", BROWSERS[who])]
        with self.opener.open(self.url + "/auth/login", timeout=60) as resp:
            resp.read()
        if not any(c.name.startswith("cloop_session") for c in self.jar):
            raise RuntimeError(f"{email} did not get a session: cookies {[c.name for c in self.jar]}")
        self.email = email

    def call(self, method, path, body=None, ok=(200, 201, 202, 204), raw=False, headers=None, token=None,
             timeout=60):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                status, ctype, payload = resp.status, resp.headers.get("Content-Type", ""), resp.read()
        except urllib.error.HTTPError as err:
            status, ctype, payload = err.code, err.headers.get("Content-Type", ""), err.read()
        if ok is not None and status not in ok:
            raise RuntimeError(f"{self.email}: {method} {path} = {status}: {payload[:600].decode('utf-8', 'replace')}")
        if raw:
            return status, ctype, payload
        return json.loads(payload) if payload else {}


class Steps:
    """Runs seeding steps, carrying on past a failed one and listing every
    failure at the end: one refused call should not cost a whole recording."""

    def __init__(self):
        self.failed: list[str] = []

    def __call__(self, what: str, fn, *args, **kw):
        try:
            out = fn(*args, **kw)
            log("seeded: " + what)
            return out
        except Exception as err:  # noqa: BLE001 — every failure is reported below
            self.failed.append(f"{what}: {err}")
            log(f"FAILED: {what}: {err}")
            return None


def project_idx(hub: Hub, path: str) -> int:
    for i, p in enumerate(hub.get("/api/projects").get("projects") or []):
        if os.path.realpath(p.get("path", "")) == os.path.realpath(path):
            return i
    raise RuntimeError(f"{path} is not in the hub's project list")


def wait_for(what: str, fn, timeout: float = 300, every: float = 2.0):
    """fn() until it returns something true, or fail after timeout."""
    until = time.time() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.time() > until:
            raise RuntimeError("timed out waiting for " + what)
        time.sleep(every)


def gen_rsa_pem() -> str:
    """A throwaway RSA key for the made-up GitHub App: generated now, so no
    key is ever written into the repository."""
    import subprocess
    return subprocess.run(["openssl", "genrsa", "2048"], check=True, capture_output=True, text=True).stdout


def seed(hub: Hub, state: dict) -> int:
    """The admin surfaces, before any project runs (a change to a project's
    readers pauses a running run)."""
    step = Steps()
    p = state["projects_by_name"]
    idx = {name: project_idx(hub, path) for name, path in p.items()}
    dev = state.get("device")
    idp = state["fakes"]["idp"]
    priya = step("sign in as Priya", Person, hub, idp, "priya")
    step("sign in as Sam", Person, hub, idp, "sam")
    # Dana signs in last, so the identity provider answers for her from here
    # on, and does what an administrator does: the audit trail, the grants and
    # the requirements then name a person rather than the static token.
    dana = step("sign in as Dana", Person, hub, idp, "dana")
    api = dana or hub

    # The fleet: the device's labels, policies and a virtual executor with a
    # USB device; a pool with a controller that has checked in.
    if dev:
        step("device labels", api.put, f"/api/executors/{dev}/labels",
             {"labels": {"region": "eu-central", "site": "fra", "rack": "b4"}})
        step("device sandbox", api.put, f"/api/executors/{dev}/sandbox",
             {"mode": "container", "engine": "docker", "runtime": "runsc",
              "image": "ghcr.io/blechschmidt/cloop-harness:latest", "network": "bridge"})
        step("device firewall", api.put, f"/api/executors/{dev}/firewall",
             {"allow_public_internet": True, "allow_cidrs": ["10.40.0.0/16"], "deny_cidrs": ["10.40.99.0/24"],
              "allow_ports": [22, 443, 5432], "resolvers": ["10.40.0.2"], "drop_denied": False})
        step("device limits", api.put, f"/api/executors/{dev}/limits",
             {"max_cpu": 8, "max_memory": "16g", "max_disk": "80g", "max_pids": 4096})
        vx = step("virtual executor", api.post, f"/api/executors/{dev}/virtuals", {
            "name": "hsm-signing", "spec": {
                "sandbox": {"mode": "container", "engine": "docker", "runtime": "runc",
                            "image": "ghcr.io/blechschmidt/cloop-harness:latest", "network": "bridge"},
                "firewall": {"allow_cidrs": ["10.40.12.0/24"], "deny_cidrs": ["10.40.12.13/32"],
                             "allow_ports": [443], "resolvers": ["10.40.0.2"]},
                "devices": [{"name": "yubihsm", "usb": {"vendor_id": "1050", "product_id": "0030",
                                                        "serial": "0031650425"}, "permissions": "rw"}]}})
        if vx:
            state["virtual"] = (vx.get("virtual_executor") or vx.get("executor") or vx).get("id")
        if dana:
            step("device audience", dana.post, f"/api/executors/{dev}/audience",
                 {"kind": "group", "value": "engineers"})
    pool = step("executor pool", hub.post, "/api/executor-pools", {
        "name": "ci-runners-eu", "labels": {"region": "eu-central", "tier": "ci"},
        "capabilities": {"harnesses": ["claude", "git"], "container_runtimes": ["docker"], "platform": "linux",
                         "arch": "amd64", "memory_mb": 8192, "cpus": 4},
        "max_runners": 12, "credential": True})
    if pool and pool.get("token"):
        state.setdefault("secrets", []).append(pool["token"])
        ctl = {"Authorization": "Bearer " + pool["token"], "X-Cloop-Pool-Controller-Protocol": "4",
               "User-Agent": "cloop-executor-controller/" + (hub.get("/api/version").get("version") or "dev")}
        step("pool controller status", hub.call, "POST", "/api/pool-controller/status",
             {"healthy": True, "storage": {"claims": 4, "bound": 4, "pending": 0, "in_use": 2, "full": 0,
                                           "retained": 0, "bytes_used": 18 << 30, "bytes_capacity": 160 << 30}},
             headers=ctl, token="")
        step("pool runners requested", hub.call, "POST", "/api/pool-controller/runners", {"count": 2},
             headers=ctl, token="")

    # Credentials, all made up: a GitHub App with a key generated now, a
    # kubeconfig, an API key, a proxy, and the knowledge connectors' tokens.
    fakes = state["fakes"]
    secrets_ = [
        ("acme-github-app", "github_app", json.dumps({"app_id": 914273, "installation_id": 58210394,
                                                      "private_key": gen_rsa_pem()})),
        ("staging-kubeconfig", "kubeconfig", STAGING_KUBECONFIG),
        ("datadog-api", "env", json.dumps({"DD_API_KEY": "demo-value-not-real"})),
        ("corp-proxy", "egress_proxy", "http://proxy.corp.example:3128"),
        ("wiki-token", "env", json.dumps({"TOKEN": fakes["wiki_pat"]})),
        ("tracker-token", "env", json.dumps({"TOKEN": fakes["jira_pat"]})),
    ]
    state.setdefault("secrets", []).extend([fakes["wiki_pat"], fakes["jira_pat"]])
    for name, kind, payload in secrets_:
        step(f"secret {name}", hub.post, "/api/secrets", {"name": name, "kind": kind, "payload": payload,
                                                           "personal": False})
    step("todo-api repositories", api.post, f"/api/projects/{idx['todo-api']}/repositories",
         {"secret": "acme-github-app", "repos": ["acme/todo-api"], "access": "write", "branches": ["cloop/*"]})
    step("landing-page repositories", api.post, f"/api/projects/{idx['landing-page']}/repositories",
         {"secret": "acme-github-app", "repos": ["acme/tidewater-site"], "access": "read"})
    kg = step("kubeconfig grant", api.post, "/api/grants", {
        "secret_ref": "staging-kubeconfig", "subject": "label:region=eu-central", "scope": "staging",
        "ttl_minutes": 10080, "contexts": ["staging-eu"], "namespaces": ["todo", "web"]})
    if kg:
        # Without the Kubernetes access monitor the namespaces are not
        # enforced; an administrator says so rather than leave it failing.
        step("kubeconfig grant, unguarded", api.post, f"/api/grants/{find_key(kg, 'id')}/unguarded",
             {"reason": "Staging only; the cluster's own RBAC limits cloop-bot to these namespaces."})
    if dev:
        step("datadog grant", api.post, "/api/grants", {
            "secret_ref": "datadog-api", "subject": f"executor:{dev}", "ttl_minutes": 10080,
            "env_keys": ["DD_API_KEY"]})
    step("egress grant", api.post, "/api/grants", {
        "source": "egress", "subject": "project:" + p["csv-report"], "hosts": ["pypi.org", "files.pythonhosted.org"],
        "ports": [443], "methods": ["GET"], "ttl_minutes": 10080})
    if priya:
        req = step("Priya asks for staging access", priya.post, "/api/grant-requests", {
            "secret_ref": "staging-kubeconfig", "subject": "project:" + p["landing-page"],
            "contexts": ["staging-eu"], "namespaces": ["web"], "ttl_minutes": 240, "wait_minutes": 10080,
            "justification": "Check the staging ingress before the Tidewater launch (WEB-31)."})
        old = step("Priya asks for the Datadog key", priya.post, "/api/grant-requests", {
            "secret_ref": "datadog-api", "subject": "project:" + p["todo-api"], "env_keys": ["DD_API_KEY"],
            "ttl_minutes": 1440, "wait_minutes": 1440,
            "justification": "Ship the todo-api request metrics to the staging dashboard."})
        if old and dana:
            rid = (old.get("request") or old).get("id")
            step("Dana approves the Datadog request", dana.post, f"/api/grant-requests/{rid}/approve",
                 {"note": "Fine for staging; one day.", "ttl_minutes": 1440})
    if dana:
        t = step("Dana mints a CI token", dana.post, "/api/tokens",
                 {"name": "todo-api-ci", "roles": ["operator"], "project_scope": ["todo-api"],
                  "expires_in_days": 90})
        if t and t.get("plaintext"):
            state["secrets"].append(t["plaintext"])
        t = step("Dana mints a reporting token", dana.post, "/api/tokens",
                 {"name": "weekly-report-bot", "roles": ["viewer"], "project_scope": ["csv-report"],
                  "expires_in_days": 30})
        if t and t.get("plaintext"):
            state["secrets"].append(t["plaintext"])

    # Knowledge: the wiki and the tracker, bound to the projects whose runs
    # read them, synced before any run so the runs cite them.
    wiki = step("Confluence source", api.post, "/api/knowledge/sources", {
        "kind": "confluence", "name": "Engineering wiki", "scope": "org", "secret_ref": "wiki-token",
        "sync_interval_minutes": 1440,
        "config": {"deployment": "datacenter", "base_url": fakes["wiki"], "spaces": ["ENG", "OPS"]}})
    jira = step("Jira source", api.post, "/api/knowledge/sources", {
        "kind": "jira", "name": "Product tracker", "scope": "org", "secret_ref": "tracker-token",
        "sync_interval_minutes": 1440,
        "config": {"deployment": "datacenter", "base_url": fakes["jira"], "projects": ["TODO", "WEB", "SALES"]}})
    for src in (wiki, jira):
        if not src:
            continue
        sid = src["source"]["id"]
        step(f"sync source {sid}", sync_source, api, sid)
    if wiki:
        for name in ("todo-api", "landing-page", "csv-report"):
            step(f"bind the wiki to {name}", hub.post, f"/api/projects/{idx[name]}/knowledge/bindings",
                 {"source_id": wiki["source"]["id"], "spaces": ["ENG"]})
    if jira:
        for name, key in (("todo-api", "TODO"), ("landing-page", "WEB"), ("csv-report", "SALES")):
            step(f"bind the tracker to {name}", hub.post, f"/api/projects/{idx[name]}/knowledge/bindings",
                 {"source_id": jira["source"]["id"], "spaces": [key]})

    # Who may read what, teams, and shares.
    step("landing-page reads todo-api", api.put, f"/api/projects/{idx['todo-api']}/readers",
         {"reader_idx": idx["landing-page"]})
    step("csv-report reads todo-api", api.put, f"/api/projects/{idx['todo-api']}/readers",
         {"reader_idx": idx["csv-report"]})
    who = api
    step("team web", who.post, "/api/teams", {"slug": "web", "name": "Web team",
                                               "description": "The Tidewater site and its launch.",
                                               "idp_group": "engineers"})
    step("team finance", who.post, "/api/teams", {"slug": "finance-analytics", "name": "Finance analytics",
                                                   "description": "Reads the weekly sales report."})
    for slug, email in (("web", PEOPLE["priya"][0]), ("finance-analytics", PEOPLE["sam"][0])):
        step(f"{email} joins {slug}", who.post, f"/api/teams/{slug}/members", {"identity": email})
    step("share landing-page with the web team", who.post, f"/api/projects/{idx['landing-page']}/members",
         {"team": "web", "role": "operator", "reason": "They run the launch."})
    step("share csv-report with finance", who.post, f"/api/projects/{idx['csv-report']}/members",
         {"team": "finance-analytics", "role": "viewer", "reason": "They read the report."})
    step("share todo-api with Sam", who.post, f"/api/projects/{idx['todo-api']}/members",
         {"identity": PEOPLE["sam"][0], "role": "viewer", "reason": "Reviews the API docs."})

    # Caps, quotas and the hub's own settings.
    step("global budget", api.put, "/api/budget/global",
         {"daily_usd_limit": 25, "daily_token_limit": 2000000, "alert_threshold_pct": 80})
    for name, usd in (("todo-api", 5), ("landing-page", 8), ("csv-report", 3)):
        step(f"{name} budget", hub.put, f"/api/budget/project?project_idx={idx[name]}",
             {"daily_usd_limit": usd, "daily_token_limit": 400000, "monthly_usd": usd * 20,
              "alert_threshold_pct": 80, "max_weekly_pct": 90, "max_five_hour_pct": 85})
        step(f"{name} Claude caps", hub.put, f"/api/claudecode-limits?project_idx={idx[name]}",
             {"max_weekly_pct": 90, "max_five_hour_pct": 85, "max_weekly_opus_pct": 40, "max_weekly_sonnet_pct": 80})
    step("Priya's quota", api.put, "/api/quotas/" + urllib.parse.quote(PEOPLE["priya"][0]),
         {"limits": {"max_projects": 5, "max_concurrent_tasks": 2, "daily_cost_usd": 40}})
    step("Sam's quota", api.put, "/api/quotas/" + urllib.parse.quote(PEOPLE["sam"][0]),
         {"limits": {"max_projects": 1, "max_concurrent_tasks": 1, "daily_cost_usd": 5}})
    step("notifications", api.put, "/api/config/notifications", {
        "dashboard_url": DEMO_URL, "webhooks": [
            {"name": "approvers", "type": "slack", "url_env": "CLOOP_NOTIFY_APPROVERS", "events": ["request.filed"]}]})
    step("speech to text", api.put, "/api/config/stt", {"groq_api_key": "demo-stt-key-not-real"})
    step("disk floor", api.put, "/api/config/disk", {"min_free_disk_mb": 2048})
    # Telemetry on: the walk through the dashboard is what it then records.
    step("telemetry", api.put, "/api/config/telemetry", {"enabled": True, "sources": ["dashboard", "glasses"]})
    step("CI rule", api.post, "/api/ci/rules", {"name": "todo-api release", "repository": "acme/todo-api",
                                                "enabled": True})
    step("legal hold", api.post, "/api/users/holds", {"identity": PEOPLE["sam"][0],
                                                       "reason": "Litigation hold LH-2026-014"})
    sc = step("SCIM credential", api.post, "/api/scim/credentials", {"name": "entra-provisioning",
                                                                    "reason": "Entra ID provisioning"})
    if sc:
        state["secrets"].append(sc.get("token") or sc.get("plaintext") or "")
    state["seed_failures"] = step.failed
    return 0


def entry_for(hub: Hub, path: str) -> dict:
    for p in hub.get("/api/projects").get("projects") or []:
        if os.path.realpath(p.get("path", "")) == os.path.realpath(path):
            return p
    raise RuntimeError(f"{path} is not in the hub's project list")


def run_project(hub: Hub, path: str, label: str, timeout: float = 900) -> dict:
    """Start a run of the project through the hub and wait for it to end:
    complete, paused or failed. The project's list entry at the end."""
    idx = project_idx(hub, path)
    hub.post(f"/api/run?project_idx={idx}", {})
    log(f"run: {label} started")
    quiet = {"n": 0}

    def ended():
        # Not running for three polls in a row: a run that could not start
        # at all (a config it cannot load) ends here too, as "initialized".
        e = entry_for(hub, path)
        busy = e.get("running") or e.get("status") in ("running", "evolving")
        quiet["n"] = 0 if busy else quiet["n"] + 1
        return e if quiet["n"] >= 3 else None
    e = wait_for(f"{label} to finish", ended, timeout=timeout, every=2)
    log(f"run: {label} ended {e.get('status')} {json.dumps(e.get('pause_reason') or {})}")
    if e.get("status") not in ("complete", "paused"):
        raise RuntimeError(f"{label} ended {e.get('status')}: see the hub's log and the project's events")
    return e


def tasks_of(hub: Hub, idx: int) -> list[dict]:
    return ((hub.get(f"/api/state?project_idx={idx}").get("plan") or {}).get("tasks")) or []


def runs(hub: Hub, state: dict) -> int:
    """Each project run for real through the hub, in the order the demo's
    story needs."""
    step = Steps()
    p = state["projects_by_name"]
    cloop = state["cloop"]
    # Runs, checks and proofs are started by Dana, as a person would start
    # them from the dashboard.
    hub = Person(hub, state["fakes"]["idp"], "dana")

    # Each project's requirements, linked to the tasks that implement them,
    # before anything runs: the agent gets them as its contract.
    li = project_idx(hub, p["landing-page"])
    spec = next(x for x in projects.PROJECTS if x["name"] == "landing-page")
    reqs = {}
    for proj in projects.PROJECTS:
        if proj.get("requirements"):
            reqs[proj["name"]] = step(f"{proj['name']}'s requirements", create_requirements, hub, proj,
                                      p[proj["name"]]) or []
    rid = reqs.get("landing-page") or []

    # todo-api: four tasks, the review gate, the README.
    e = step("todo-api, to its review gate", run_project, hub, p["todo-api"], "todo-api")
    if e and (e.get("pause_reason") or {}).get("code") == "approval":
        gate = e["pause_reason"].get("task_id")
        step("Dana approves the gate", hub.post,
             f"/api/tasks/{gate}/approve?project_idx={project_idx(hub, p['todo-api'])}", {})
        step("todo-api, after the gate", run_project, hub, p["todo-api"], "todo-api")

    # landing-page: the link check fails, is looked into and retried.
    step("landing-page, first run", run_project, hub, p["landing-page"], "landing-page")
    failed = [t for t in tasks_of(hub, li) if t.get("status") == "failed"]
    with open(os.path.join(p["landing-page"], ".cloop", projects.RETRY_FLAG), "w") as fh:
        fh.write("the FAQ is wanted\n")
    for t in failed:
        step(f"retry landing-page task {t['id']}", hub.post, f"/api/task/status?project_idx={li}",
             {"id": t["id"], "status": "pending"})
    if failed:
        step("landing-page, the retry", run_project, hub, p["landing-page"], "landing-page")
    for name in ("todo-api", "landing-page"):
        step(f"trace {name}'s commits", run_cli, cloop, p[name], "trace", "--no-model", "--limit", "200")
    for name in ("todo-api", "landing-page"):
        i = project_idx(hub, p[name])
        check = step(f"check {name}'s requirements", hub.post, f"/api/requirement-runs?project_idx={i}", {})
        if check:
            step(f"wait for {name}'s check", wait_requirement_run, hub, i, find_key(check, "run_id"))
    if rid and rid[0]:
        # R-1's test is a command, not a file, so cloop cannot tell which
        # commit came before its implementation: name it, the commit before
        # task 1's.
        base = step("R-1's base", git_out, p["landing-page"], "rev-parse", "--verify",
                    git_out(p["landing-page"], "log", "--format=%H", "-F", "--grep=(Task 1)").split()[0] + "^")
        proof = step("prove R-1", hub.post, f"/api/requirements/{rid[0]}/prove?project_idx={li}",
                     {"base": (base or "").strip()})
        if proof:
            step("wait for the proof", wait_requirement_run, hub, li, find_key(proof, "run_id"))
    feat = step("the dark-mode feature", hub.post, f"/api/projects/{li}/features", {
        "name": "Dark mode", "description": "A dark colour scheme that follows the reader's system setting.",
        "base": "main", "tasks": [spec["feature"]["task"][0]]})
    if feat and feat.get("path"):
        state["projects_by_name"]["dark-mode"] = feat["path"]
        step("dark-mode, its run", run_project, hub, feat["path"], "dark-mode")

    # csv-report: parses the export, then runs out of usage.
    step("csv-report, until the usage cap", run_project, hub, p["csv-report"], "csv-report")
    ci = project_idx(hub, p["csv-report"])
    check = step("check csv-report's requirements", hub.post, f"/api/requirement-runs?project_idx={ci}", {})
    if check:
        step("wait for csv-report's check", wait_requirement_run, hub, ci, find_key(check, "run_id"))

    # What people do with a project besides running it: ask it things, note
    # things down, replay a task on another model, and move a project.
    ti = project_idx(hub, p["todo-api"])
    for i, (title, body, tags) in ((ti, KB["todo-api"][0]), (ti, KB["todo-api"][1]),
                                   (li, KB["landing-page"][0]), (ci, KB["csv-report"][0])):
        step(f"knowledge base: {title}", hub.post, f"/api/kb?project_idx={i}",
             {"title": title, "body": body, "tags": tags})
    for i, msg in ((ti, "what is left to do?"), (ci, "show me the tasks")):
        step(f"chat: {msg}", hub.call, "POST", f"/api/chat?project_idx={i}", {"message": msg}, timeout=180)
    # The site goes on: a task added after its launch, not run yet.
    step("landing-page's next task", hub.post, f"/api/tasks?project_idx={li}", {
        "title": "Translate the page into German", "priority": 3,
        "description": "A /de/ copy of the page with the same sections; the button says Kostenlos starten."})
    step("replay todo-api's store task on the mock model", run_cli, cloop, p["todo-api"], "task", "replay", "2",
         "--provider", "mock", "--model", "mock-model")
    state["run_failures"] = step.failed
    return 0


# Knowledge base entries: (title, body, tags) per project.
KB = {
    "todo-api": [
        ("Error responses", "Every error is {\"error\": \"...\"} with a 4xx status; see the HTTP API style "
         "guide in the engineering wiki.", ["api", "conventions"]),
        ("Running locally", "go run . listens on :8080; ADDR=:9090 go run . to move it. GET /healthz answers ok.",
         ["howto"]),
    ],
    "landing-page": [("Brand voice", "Short sentences, no exclamation marks, 24-hour tide times. The button "
                      "always says Start free.", ["copy"])],
    "csv-report": [("Report week", "A week runs Monday 00:00 to Sunday 23:59, Europe/Berlin; revenue is net of "
                    "VAT, in euros.", ["definitions"])],
}


def create_requirements(hub: Hub, spec: dict, path: str) -> list:
    """A project's requirements, approved, each with its tests, and the links
    from the tasks that implement them. Their ids, in order."""
    idx = project_idx(hub, path)
    ids = []
    for title, prio, details, tests in spec["requirements"]:
        r = hub.post(f"/api/requirements?project_idx={idx}", {
            "title": title, "description": details, "priority": prio, "status": "approved",
            "tests": [{"name": n, "command": c, "timeout_seconds": 30} for n, c in tests]})
        ids.append(find_key(r, "id"))
    links = dict(spec.get("links") or {})
    for n, t in enumerate(spec["tasks"], start=1):
        if len(t) > 6:
            links[n] = t[6]
    by_title = {t["title"]: t["id"] for t in tasks_of(hub, idx)}
    for n, want in links.items():
        tid = by_title.get(spec["tasks"][n - 1][0])
        if tid:
            hub.put(f"/api/tasks/{tid}?project_idx={idx}", {"requirements": [ids[k - 1] for k in want]})
    return ids


def find_key(doc, key: str):
    """The first value under key anywhere in doc."""
    if isinstance(doc, dict):
        if doc.get(key) not in (None, ""):
            return doc[key]
        doc = list(doc.values())
    if isinstance(doc, list):
        for v in doc:
            found = find_key(v, key)
            if found not in (None, ""):
                return found
    return None


def wait_requirement_run(hub: Hub, idx: int, run_id: str):
    """Until a requirement check or proof is no longer running."""
    if not run_id:
        raise RuntimeError("the hub answered with no run_id")

    def done():
        st = find_key(hub.get(f"/api/requirement-runs/{run_id}?project_idx={idx}"), "state")
        return st if st and st not in ("running", "queued", "pending", "starting") else None
    return wait_for(f"requirement run {run_id}", done, timeout=300)


def git_out(cwd: str, *args: str) -> str:
    return projects._git(cwd, *args)


def run_cli(cloop: str, cwd: str, *args: str) -> str:
    import subprocess
    out = subprocess.run([cloop, *args], cwd=cwd, capture_output=True, text=True, timeout=300)
    if out.returncode != 0:
        raise RuntimeError(f"cloop {' '.join(args)}: {out.stderr.strip()[-600:]}")
    return out.stdout


STAGING_KUBECONFIG = """apiVersion: v1
kind: Config
clusters:
- name: staging-eu
  cluster:
    server: https://k8s.staging.demo.example.com:6443
contexts:
- name: staging-eu
  context: {cluster: staging-eu, user: cloop-bot, namespace: todo}
current-context: staging-eu
users:
- name: cloop-bot
  user: {token: demo-token-not-real}
"""


def sync_source(hub: Hub, sid: int):
    st, _, body = hub.call("POST", f"/api/knowledge/sources/{sid}/sync", {}, ok=None, raw=True)
    if st not in (200, 202, 409):
        raise RuntimeError(f"sync = {st}: {body[:300]!r}")

    def done():
        s = hub.get(f"/api/knowledge/sources/{sid}")
        sync = (s.get("source") or s).get("sync") or {}
        return sync if sync.get("status") and not sync.get("running") else None
    sync = wait_for(f"source {sid} to sync", done, timeout=180)
    if sync.get("status") not in ("ok", "complete", "succeeded"):
        raise RuntimeError(f"source {sid} synced with {sync}")
    return sync


# ──────────────────────────────────────────────────────── the edge device

class WebSocket:
    """A WebSocket client in the standard library: enough of RFC 6455 for
    the agent protocol's JSON text frames."""

    def __init__(self, url: str, headers: dict[str, str]):
        import socket
        u = urllib.parse.urlsplit(url)
        self.sock = socket.create_connection((u.hostname, u.port or 80), timeout=60)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [f"GET {u.path}{'?' + u.query if u.query else ''} HTTP/1.1", f"Host: {u.hostname}:{u.port}",
                 "Upgrade: websocket", "Connection: Upgrade", f"Sec-WebSocket-Key: {key}",
                 "Sec-WebSocket-Version: 13"] + [f"{k}: {v}" for k, v in headers.items()]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("the hub closed the connection during the handshake")
            buf += chunk
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise RuntimeError("handshake refused: " + head.decode(errors="replace")[:400])
        self.wlock = threading.Lock()

    def _read(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _send(self, opcode: int, data: bytes) -> None:
        head = bytes([0x80 | opcode])
        n = len(data)
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        mask = os.urandom(4)
        with self.wlock:
            self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def send(self, obj) -> None:
        self._send(0x1, json.dumps(obj).encode())

    def recv(self):
        """The next text message, decoded; None when the socket closes."""
        parts = b""
        while True:
            b0, b1 = self._read(2)
            opcode, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self._read(2), "big")
            elif n == 127:
                n = int.from_bytes(self._read(8), "big")
            mask = self._read(4) if b1 & 0x80 else b""
            data = self._read(n)
            if mask:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self._send(0xA, data)
                continue
            if opcode in (0x1, 0x2, 0x0):
                parts += data
                if b0 & 0x80:
                    return json.loads(parts.decode())


# The device the demo shows: invented, down to its kernel and its serial
# numbers. Its USB inventory is what the virtual executor's picker offers.
DEVICE_KERNEL = {
    "schema": 1, "release": "6.8.0-49-generic", "version": "#49-Ubuntu SMP PREEMPT_DYNAMIC Mon Nov  4 02:06:24 UTC 2024",
    "machine": "x86_64",
    "proc_version": "Linux version 6.8.0-49-generic (buildd@lcy02-amd64-103) (x86_64-linux-gnu-gcc-13 (Ubuntu "
                    "13.2.0-23ubuntu4) 13.2.0) #49-Ubuntu SMP PREEMPT_DYNAMIC Mon Nov  4 02:06:24 UTC 2024",
    "boot_id": "6f1c2a4e-3b7d-4e19-9a52-0c8d7e6b5a31", "uptime_seconds": 1209600.0,
    "dmi_vendor": "Supermicro", "dmi_product": "SYS-E300-12D",
}
DEVICE_USB = [
    {"port": "1-2", "bus": 1, "dev": 4, "vendor_id": "0483", "product_id": "374b",
     "manufacturer": "STMicroelectronics", "product": "STM32 STLink", "serial": "0669FF485671",
     "node": "/dev/bus/usb/001/004"},
    {"port": "1-3", "bus": 1, "dev": 5, "vendor_id": "1050", "product_id": "0030", "manufacturer": "Yubico",
     "product": "YubiHSM 2", "serial": "0031650425", "node": "/dev/bus/usb/001/005"},
]


def device_capabilities(version: str) -> dict:
    return {"os": "linux", "arch": "amd64", "cpus": 12, "memory_mb": 65536, "container_runtimes": ["docker"],
            "harnesses": ["claude", "git"], "workdir_root": "/srv/cloop/work", "workspace_provisioning": True,
            "write_back": True, "branch_bundles": True, "max_concurrent": 4, "virtualization": True,
            "usb_devices": DEVICE_USB, "packet_filter": True, "host_sandbox": True, "denial_log": True,
            "forwarded_usb": True, "forwarded_l2": True, "oci_runtimes": ["runc", "runsc"],
            "update_channel": "stable", "host_kernel": DEVICE_KERNEL}


def probe_evidence(sandbox: dict) -> dict:
    """What the isolation probe would read in a sandbox under the runtime
    named: gVisor's own kernel for runsc, the device's for runc."""
    if sandbox.get("runtime") == "runsc":
        return {"schema": 1, "release": "4.4.0", "version": "#1 SMP Sun Jan 10 15:06:54 PST 2016",
                "machine": "x86_64", "proc_version": "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016",
                "boot_id": "c3f0a9d2-58e1-4b6a-9e37-1d2c4b8a7f60", "uptime_seconds": 2.5,
                "gvisor": ["/proc/version names gVisor's kernel", "dmesg: Starting gVisor..."]}
    return dict(DEVICE_KERNEL)


def run_agent(hub: Hub, state: dict, name: str, labels: dict, stop_file: str) -> tuple:
    """Enroll as a device and stay connected until stop_file appears."""
    version = hub.get("/api/version").get("version", "")
    enroll = hub.post("/api/executors/enroll", {"name": name, "ttl_minutes": 60, "workdir_root": "/srv/cloop/work",
                                                "labels": labels})
    server = hub.url.replace("http://", "ws://") + "/api/executors/connect"
    ws = WebSocket(server, {"Authorization": "Bearer " + enroll["token"]})
    ws.send({"v": 1, "type": "hello", "id": "hello", "payload": {
        "protocol_version": 31, "agent_id": "", "name": name, "agent_version": version,
        "capabilities": device_capabilities(version)}})
    welcome = ws.recv()
    if not welcome or welcome.get("type") != "welcome":
        raise RuntimeError(f"no welcome: {welcome}")
    device = welcome["payload"]["executor_id"]
    state.setdefault("secrets", []).extend([enroll["token"], welcome["payload"].get("credential", "")])
    state["device"] = device
    log(f"agent: enrolled as {device}")
    alive = threading.Event()
    alive.set()

    def beat():
        n = 0
        while alive.is_set() and not os.path.exists(stop_file):
            n += 1
            try:
                ws.send({"v": 31, "type": "heartbeat", "id": f"hb-{n}", "payload": {"seq": n}})
            except OSError:
                return
            for _ in range(20):
                if os.path.exists(stop_file):
                    break
                time.sleep(0.5)
        alive.clear()
        try:
            ws.sock.close()
        except OSError:
            pass

    threading.Thread(target=beat, daemon=True).start()
    return device, ws, alive


def agent_loop(ws, alive) -> None:
    """Answer the hub's requests until the socket closes."""
    while alive.is_set():
        try:
            f = ws.recv()
        except (EOFError, OSError):
            break
        if f is None:
            break
        t, fid, payload = f.get("type"), f.get("id", ""), f.get("payload") or {}
        if t == "isolation_probe":
            sb = payload.get("sandbox") or {}
            ws.send({"v": 31, "type": "isolation_evidence", "id": fid, "payload": {
                "evidence": probe_evidence(sb), "host": DEVICE_KERNEL, "engine": sb.get("engine") or "docker",
                "image": sb.get("image") or "", "engine_kernel": DEVICE_KERNEL["release"]}})
        elif t == "inventory_req":
            ws.send({"v": 31, "type": "inventory", "id": fid,
                     "payload": {"capabilities": device_capabilities("")}})
        elif t not in ("heartbeat_ack", "ack"):
            log(f"agent: ignored {t}")
    alive.clear()


# ─────────────────────────────────────────────────────────── the projects

def setup(state: dict) -> int:
    """The three projects, as someone would start them: a git repository
    with a first commit, `cloop init`, and the plan."""
    import subprocess
    cloop, root = state["cloop"], state["projects_root"]
    os.makedirs(root, exist_ok=True)
    state["projects_by_name"] = {}
    for spec in projects.PROJECTS:
        d = os.path.join(root, spec["name"])
        os.makedirs(d)
        files = dict(spec["start"])
        files[".gitignore"] = ".cloop/*\n!.cloop/requirements.yaml\n"
        for rel, content in files.items():
            os.makedirs(os.path.dirname(os.path.join(d, rel)) or d, exist_ok=True)
            with open(os.path.join(d, rel), "w", encoding="utf-8") as fh:
                fh.write(content)
            if rel.endswith(".sh"):
                os.chmod(os.path.join(d, rel), 0o755)
        projects._git(d, "init", "-q", "-b", "main")
        projects._git(d, "add", "-A")
        projects._git(d, "commit", "-q", "-m", "Initial commit")
        # Where the code lives; nothing fetches or pushes it during the
        # recording.
        projects._git(d, "remote", "add", "origin", spec["origin"])
        provider = "anthropic" if spec["name"] == "landing-page" else "claudecode"
        run_cli(cloop, d, "init", "--provider", provider, "--skip-clarify", "--model",
                "claude-sonnet-4-6" if provider == "anthropic" else "claude-opus-5-5",
                "--instructions", spec["instructions"], spec["goal"])
        if provider == "anthropic":
            # Point the project's Anthropic provider at the fake Messages API:
            # the block `cloop init` wrote, edited in place (a second block
            # would be a duplicate key, and the config would no longer load).
            cfg = os.path.join(d, ".cloop", "config.yaml")
            with open(cfg, encoding="utf-8") as fh:
                text = fh.read()
            m = re.search(r"^anthropic:\n((?:[ \t]+.*\n)*)", text, re.M)
            if not m:
                raise RuntimeError(f"{cfg} has no anthropic block to point at the fake API")
            base = state["fakes"]["messages"]   # with /v1, as the provider's base URL is
            block = re.sub(r"^(\s+)api_key: .*$", r"\1api_key: demo-key-not-real", m.group(1), flags=re.M)
            block = re.sub(r"^(\s+)base_url: .*$", lambda b: f"{b.group(1)}base_url: {base}", block, flags=re.M)
            block = re.sub(r"^(\s+)model: .*$", r"\1model: claude-sonnet-4-6", block, flags=re.M)
            with open(cfg, "w", encoding="utf-8") as fh:
                fh.write(text[:m.start(1)] + block + text[m.end(1):])
        plan = {"goal": spec["goal"], "tasks": []}
        epic = {"todo-api": "epic:api", "landing-page": "epic:launch", "csv-report": "epic:reporting"}[spec["name"]]
        for i, t in enumerate(spec["tasks"], start=1):
            title, desc, role, prio, minutes, tags = t[:6]
            task = {"id": i, "title": title, "description": desc, "priority": prio, "status": "pending",
                    "role": role, "tags": tags + [epic], "estimated_minutes": minutes,
                    "risk_score": (3 + i * 2) % 9 + 1, "impact_score": (8 - i) % 9 + 1}
            if spec["name"] == "todo-api" and i > 1:
                task["depends_on"] = [i - 1]
            if spec["name"] == "csv-report" and i > 1:
                task["depends_on"] = [i - 1]
                task["assignee"] = PEOPLE["priya"][0]
            plan["tasks"].append(task)
        with open(os.path.join(d, ".cloop", "plan-import.json"), "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        run_cli(cloop, d, "plan", "import", ".cloop/plan-import.json", "--yes")
        if spec.get("gate"):
            g = spec["gate"]
            run_cli(cloop, d, "task", "gate", "add", "--after", str(g["after"]), "--title", g["title"],
                    "--note", "A second person reads the handlers and the tests before the README is written.")
        # cloop init adds its env file to .gitignore; committed, so the
        # project's tree is clean when its requirements are checked.
        if projects._git(d, "status", "--porcelain").strip():
            projects._git(d, "add", "-A")
            projects._git(d, "commit", "-q", "-m", "Ignore cloop's local files")
        state["projects_by_name"][spec["name"]] = d
        log(f"setup: {spec['name']} in {d}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup").add_argument("--state", required=True)
    for name in ("seed", "runs", "crawl", "agent"):
        p = sub.add_parser(name)
        p.add_argument("--hub", required=True)
        p.add_argument("--token-file", required=True)
        p.add_argument("--state", required=True, help="the recording's state file (JSON), read and updated")
    sub.choices["crawl"].add_argument("--walk", required=True, help="walk.js's recording")
    sub.choices["crawl"].add_argument("--out", required=True)
    sub.choices["agent"].add_argument("--stop", required=True, help="the agent disconnects when this file appears")
    sub.choices["agent"].add_argument("--out", required=True, help="written with the device's id once enrolled")
    w = sub.add_parser("write")
    w.add_argument("--state", required=True)
    w.add_argument("--crawl", required=True)
    w.add_argument("--out", default=FIXTURES)
    args = ap.parse_args()
    if args.cmd == "write":
        return write(args)
    with open(args.state, encoding="utf-8") as fh:
        state = json.load(fh)
    if args.cmd == "setup":
        rc = setup(state)
    else:
        with open(args.token_file, encoding="utf-8") as fh:
            hub = Hub(args.hub, fh.read().strip())
        if args.cmd == "agent":
            device, ws, alive = run_agent(hub, state, "edge-fra-07", {"region": "eu-central", "site": "fra"},
                                          args.stop)
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump({"device": device, "secrets": state.get("secrets", [])}, fh)
            agent_loop(ws, alive)
            return 0
        rc = {"seed": seed, "runs": runs}.get(args.cmd, None)
        rc = rc(hub, state) if rc else crawl(hub, state, args)
    with open(args.state + ".tmp", "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=1)
    os.replace(args.state + ".tmp", args.state)
    return rc


if __name__ == "__main__":
    sys.exit(main())
