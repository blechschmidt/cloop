#!/usr/bin/env python3
"""fakes.py — the outside world a demo recording talks to, made up.

record-fixtures.sh runs this beside the throwaway hub. It serves, until it is
killed:

  idp        an OpenID Connect provider on loopback that signs in whoever
             POST /_identity last named, without asking: the hub's single
             sign-on, so the demo is recorded as a signed-in administrator
             and teams, shares and sessions have someone in them.
  usage      Claude's usage endpoint (/api/oauth/usage), which the recording's
             cloop is built to ask instead of api.anthropic.com
             (record-fixtures.sh links that address in), so the limit views
             show a five-hour and a weekly window.
  messages   the Anthropic Messages API (/v1/messages), which landing-page is
             run against: it answers the way stub-claude.py does, through
             projects.perform, and reports token usage and rate-limit headers,
             so the demo's costs come from cloop's own accounting.
  wiki, jira Confluence and Jira Data Center, over TLS on a private address of
             this machine (the knowledge connectors refuse loopback), with a
             CA made for the run; the hub trusts it through SSL_CERT_FILE.

Everything is invented: the people, pages, issues, tokens and keys. The keys
are generated per run and the credentials the connectors are given are random.
Standard library and the openssl command only.

    fakes.py --work DIR --projects-root DIR --private-ip ADDR --ready FILE
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import projects  # noqa: E402

LOG_LOCK = threading.Lock()


def log(msg: str) -> None:
    with LOG_LOCK:
        print("fakes: " + msg, file=sys.stderr, flush=True)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def openssl(*args: str, data: bytes | None = None) -> bytes:
    out = subprocess.run(["openssl", *args], input=data, capture_output=True)
    if out.returncode != 0:
        raise RuntimeError("openssl " + " ".join(args) + ": " + out.stderr.decode(errors="replace"))
    return out.stdout


class Handler(BaseHTTPRequestHandler):
    """A request handler that routes to the server's `route` function."""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet: the hub's own log says enough
        pass

    def body(self) -> bytes:
        return self._body

    def _read_body(self) -> None:
        # Read before anything is answered: a reply sent with the body
        # unread leaves it on a kept-alive connection, to be parsed as the
        # next request.
        n = int(self.headers.get("Content-Length") or 0)
        self._body = self.rfile.read(n) if n else b""

    def send(self, status: int, payload, ctype: str = "application/json", headers: dict | None = None):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._read_body()
        self.server.route(self, "GET")

    def do_POST(self):
        self._read_body()
        self.server.route(self, "POST")


def serve(host: str, route, tls: ssl.SSLContext | None = None) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, 0), Handler)
    srv.daemon_threads = True
    srv.route = route
    if tls:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ─────────────────────────────────────────────────────────────────── the IdP

class IdP:
    """Signs in whoever was last named, with the groups named, at once."""

    def __init__(self, work: str):
        self.key = os.path.join(work, "idp.key")
        openssl("genrsa", "-out", self.key, "2048")
        modulus = openssl("rsa", "-in", self.key, "-noout", "-modulus").decode().strip().split("=", 1)[1]
        self.n = b64url(bytes.fromhex(modulus))
        self.who = {"email": "nobody@demo.example.com", "name": "Nobody", "groups": []}
        self.codes: dict[str, dict] = {}
        self.refresh: dict[str, dict] = {}
        self.lock = threading.Lock()
        self.url = ""

    def sign(self, claims: dict) -> str:
        head = b64url(json.dumps({"alg": "RS256", "kid": "demo-1", "typ": "JWT"}).encode())
        body = b64url(json.dumps(claims).encode())
        sig = openssl("dgst", "-sha256", "-sign", self.key, data=f"{head}.{body}".encode())
        return f"{head}.{body}.{b64url(sig)}"

    def route(self, h: Handler, method: str):
        u = urllib.parse.urlsplit(h.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        if u.path == "/.well-known/openid-configuration":
            return h.send(200, {"issuer": self.url, "authorization_endpoint": self.url + "/authorize",
                                "token_endpoint": self.url + "/token", "jwks_uri": self.url + "/jwks",
                                "userinfo_endpoint": self.url + "/userinfo",
                                "response_types_supported": ["code"], "subject_types_supported": ["public"],
                                "id_token_signing_alg_values_supported": ["RS256"],
                                "code_challenge_methods_supported": ["S256"],
                                "scopes_supported": ["openid", "email", "profile", "offline_access"]})
        if u.path == "/jwks":
            return h.send(200, {"keys": [{"kty": "RSA", "kid": "demo-1", "use": "sig", "alg": "RS256",
                                          "n": self.n, "e": "AQAB"}]})
        if u.path == "/_identity" and method == "POST":
            who = json.loads(h.body() or b"{}")
            with self.lock:
                self.who = {"email": who["email"], "name": who.get("name", who["email"]),
                            "groups": who.get("groups", [])}
            return h.send(200, {"ok": True})
        if u.path == "/authorize":
            with self.lock:
                code = "code-" + secrets.token_hex(8)
                self.codes[code] = dict(self.who, nonce=q.get("nonce", ""), client=q.get("client_id", ""),
                                        auth_time=int(time.time()))
            cb = urllib.parse.urlsplit(q.get("redirect_uri", ""))
            cq = urllib.parse.parse_qsl(cb.query) + [("code", code), ("state", q.get("state", ""))]
            loc = urllib.parse.urlunsplit((cb.scheme, cb.netloc, cb.path, urllib.parse.urlencode(cq), ""))
            h.send_response(302)
            h.send_header("Location", loc)
            h.send_header("Content-Length", "0")
            h.end_headers()
            return None
        if u.path == "/token" and method == "POST":
            form = dict(urllib.parse.parse_qsl(h.body().decode()))
            with self.lock:
                if form.get("grant_type") == "refresh_token":
                    who = self.refresh.get(form.get("refresh_token", ""))
                    if who:
                        who = dict(who, nonce="")
                else:
                    who = self.codes.pop(form.get("code", ""), None)
                if not who:
                    return h.send(400, {"error": "invalid_grant"})
                rt = "rt-" + secrets.token_hex(12)
                self.refresh[rt] = who
            sub = "demo-" + re.sub(r"[^a-z0-9]+", "-", who["email"].lower())
            claims = {"iss": self.url, "sub": sub, "aud": who.get("client") or form.get("client_id", ""),
                      "iat": int(time.time()), "exp": int(time.time()) + 3600, "auth_time": who["auth_time"],
                      "email": who["email"], "email_verified": True, "name": who["name"],
                      "preferred_username": who["email"], "groups": who["groups"]}
            if who.get("nonce"):
                claims["nonce"] = who["nonce"]
            return h.send(200, {"access_token": "at-" + secrets.token_hex(8), "token_type": "Bearer",
                                "expires_in": 3600, "id_token": self.sign(claims), "refresh_token": rt,
                                "scope": "openid email profile offline_access"})
        if u.path == "/userinfo":
            with self.lock:
                who = dict(self.who)
            return h.send(200, {"sub": "demo-" + re.sub(r"[^a-z0-9]+", "-", who["email"].lower()),
                                "email": who["email"], "name": who["name"], "groups": who["groups"]})
        return h.send(404, {"error": "not_found"})


# ──────────────────────────────────────────────────────────── Claude's usage

def usage_route(h: Handler, method: str):
    if urllib.parse.urlsplit(h.path).path != "/api/oauth/usage":
        return h.send(404, {"error": {"type": "not_found_error"}})
    t = now().replace(second=0, microsecond=0)
    at = lambda hours: (t + dt.timedelta(hours=hours)).isoformat()  # noqa: E731
    return h.send(200, {
        "five_hour": {"utilization": 37.0, "resets_at": at(3)},
        "seven_day": {"utilization": 61.0, "resets_at": at(4 * 24 + 5)},
        "seven_day_opus": {"utilization": 18.0, "resets_at": at(4 * 24 + 5)},
        "seven_day_sonnet": {"utilization": 44.0, "resets_at": at(4 * 24 + 5)},
        "extra_usage": {"is_enabled": True, "monthly_limit": 5000, "used_credits": 1240, "utilization": 24.8},
        "limits": [{"kind": "weekly_scoped", "group": "weekly", "percent": 7, "resets_at": at(4 * 24 + 5),
                    "scope": {"model": {"id": None, "display_name": "Fable"}, "surface": None},
                    "is_active": False}],
    })


# ────────────────────────────────────────────────────── the Messages API

class Messages:
    """The Anthropic Messages API, answering as projects.perform does."""

    def __init__(self, projects_root: str):
        self.root = projects_root
        self.n = 0
        self.lock = threading.Lock()

    def project_dir(self, prompt: str) -> str:
        _, title = projects.current_task(prompt)
        name, _ = projects.task_entry(title or "")
        if name is None:
            return ""
        feature = next((p.get("feature") for p in projects.PROJECTS if p["name"] == name), None)
        if feature and feature["task"][0] == title:
            return os.path.join(self.root, name, ".cloop", "features", feature["slug"])
        return os.path.join(self.root, name)

    def route(self, h: Handler, method: str):
        if method != "POST" or urllib.parse.urlsplit(h.path).path != "/v1/messages":
            return h.send(404, {"type": "error", "error": {"type": "not_found_error", "message": "not here"}})
        req = json.loads(h.body() or b"{}")
        prompt = "\n".join(c if isinstance(c, str) else "".join(b.get("text", "") for b in c)
                           for c in (m.get("content", "") for m in req.get("messages", [])))
        cwd = self.project_dir(prompt)
        try:
            text = projects.perform(cwd, prompt) if cwd else "Nothing to do here.\n\nTASK_DONE"
        except Exception as err:  # a failed commit is the agent's failure, not the API's
            text = f"I could not finish: {err}\n\nTASK_FAILED"
        with self.lock:
            self.n += 1
            n = self.n
        model = req.get("model") or "claude-sonnet-4-6"
        usage_in = len(prompt) // 4 + len(req.get("system") or "") // 4 + 900
        usage_out = len(text) // 4 + 640 + (n * 37) % 300
        reset = (now() + dt.timedelta(seconds=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {"request-id": f"req_demo{n:012d}",
                   "anthropic-ratelimit-requests-limit": "50", "anthropic-ratelimit-requests-remaining": "49",
                   "anthropic-ratelimit-requests-reset": reset,
                   "anthropic-ratelimit-input-tokens-limit": "40000",
                   "anthropic-ratelimit-input-tokens-remaining": str(max(0, 40000 - usage_in)),
                   "anthropic-ratelimit-input-tokens-reset": reset,
                   "anthropic-ratelimit-output-tokens-limit": "8000",
                   "anthropic-ratelimit-output-tokens-remaining": str(max(0, 8000 - usage_out)),
                   "anthropic-ratelimit-output-tokens-reset": reset,
                   "anthropic-ratelimit-tokens-limit": "48000",
                   "anthropic-ratelimit-tokens-remaining": str(max(0, 48000 - usage_in - usage_out)),
                   "anthropic-ratelimit-tokens-reset": reset}
        msg_id = f"msg_demo{n:016d}"
        if not req.get("stream"):
            return h.send(200, {"id": msg_id, "type": "message", "role": "assistant", "model": model,
                                "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                                "stop_sequence": None,
                                "usage": {"input_tokens": usage_in, "output_tokens": usage_out,
                                          "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}},
                          headers=headers)
        events = [
            ("message_start", {"type": "message_start", "message": {
                "id": msg_id, "type": "message", "role": "assistant", "model": model, "content": [],
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": usage_in, "output_tokens": 1}}}),
            ("content_block_start", {"type": "content_block_start", "index": 0,
                                     "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                     "delta": {"type": "text_delta", "text": text}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                               "usage": {"output_tokens": usage_out}}),
            ("message_stop", {"type": "message_stop"}),
        ]
        data = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode()
        return h.send(200, data, ctype="text/event-stream", headers=headers)


# ───────────────────────────────────────────────── Confluence and Jira

PAGES = [
    # id, space, title, ancestors, body (storage HTML), days since edited
    ("3001", "ENG", "Engineering handbook", [], "<p>How the engineering team works: reviews, releases and the "
     "on-call rota. Start with the release checklist.</p>", 30),
    ("3002", "ENG", "Release checklist", ["3001"], "<h2>Before tagging a release</h2><ol><li>go vet and every "
     "test pass on main.</li><li>The README lists every endpoint the service answers.</li><li>An API change "
     "has been reviewed by a second person.</li></ol>", 6),
    ("3003", "ENG", "HTTP API style guide", ["3001"], "<p>Every error is JSON: <code>{\"error\": \"...\"}</code> "
     "with a 4xx status. An unknown id is a 404, never an empty 200. Collections are sorted oldest first.</p>", 12),
    ("3004", "ENG", "Tidewater brand voice", ["3001"], "<p>Tidewater speaks plainly: short sentences, no "
     "exclamation marks, tide times in 24-hour clock. The call to action is always <em>Start free</em>.</p>", 3),
    ("3005", "ENG", "Sales report definitions", ["3001"], "<p>Revenue is in euros, net of VAT. The four "
     "regions are North, South, East and West. A week starts on Monday at 00:00 Europe/Berlin.</p>", 9),
    ("4001", "OPS", "On-call handbook", [], "<p>Page the primary first; escalate to the duty manager after "
     "fifteen minutes without an answer.</p>", 20),
]

ISSUES = [
    # id, key, summary, description, comment, status, type, priority, labels, days since updated
    ("51012", "TODO-12", "Unknown todo ids answer with an HTML 404 page",
     "GET /todos/42 returns the router's HTML page. Clients expect {\"error\": ...} like every other error.",
     "Agreed: use the JSON error helper for every 4xx.", "In Progress", "Bug", "High", ["api"], 2),
    ("51015", "TODO-15", "Document the PATCH payload", "The README does not say what PATCH /todos/{id} accepts.",
     "", "To Do", "Task", "Medium", ["docs"], 4),
    ("52031", "WEB-31", "The FAQ link in the navigation goes nowhere",
     "The nav has an FAQ link but the page has no FAQ section.", "Marketing wants the FAQ, not a removed link.",
     "In Progress", "Bug", "High", ["landing"], 1),
    ("52034", "WEB-34", "Search results show no description",
     "Search engines show the first words of the page. Add a meta description under 160 characters.", "",
     "To Do", "Story", "Medium", ["seo"], 5),
    ("53008", "SALES-8", "The weekly report should start on Monday",
     "Finance reads the report on Monday morning; the week must run Monday to Sunday.", "", "To Do", "Story",
     "Medium", ["report"], 3),
]

JIRA_PROJECTS = {"TODO": "Todo API", "WEB": "Tidewater website", "SALES": "Sales reporting"}


class Atlassian:
    """Confluence and Jira Data Center: the REST calls the connectors make."""

    def __init__(self):
        self.wiki_pat = "wiki" + secrets.token_hex(20)
        self.jira_pat = "jira" + secrets.token_hex(20)
        self.wiki_base = ""
        self.jira_base = ""
        self.t0 = now()

    def when(self, days: float, jira=False) -> str:
        t = self.t0 - dt.timedelta(days=days, hours=2)
        return t.strftime("%Y-%m-%dT%H:%M:%S.000+0000") if jira else t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def page_json(self, p, expand: str) -> dict:
        pid, space, title, ancestors, body, days = p
        out = {"id": pid, "type": "page", "status": "current", "title": title, "space": {"key": space},
               "version": {"when": self.when(days)},
               "_links": {"webui": "/display/" + space + "/" + urllib.parse.quote_plus(title)}}
        if "body.storage" in expand:
            out["body"] = {"storage": {"value": body, "representation": "storage"}}
        if "ancestors" in expand:
            out["ancestors"] = [{"id": a, "title": t[2]} for a in ancestors for t in PAGES if t[0] == a]
        if "restrictions.read.restrictions" in expand:
            out["restrictions"] = {"read": {"restrictions": self.restrictions()}}
        return out

    @staticmethod
    def restrictions() -> dict:
        return {"user": {"results": [], "size": 0}, "group": {"results": [], "size": 0}}

    def wiki(self, h: Handler, method: str):
        u = urllib.parse.urlsplit(h.path)
        q = urllib.parse.parse_qs(u.query)
        if h.headers.get("Authorization") != "Bearer " + self.wiki_pat:
            return h.send(401, {"message": "not signed in"})
        path = u.path.removeprefix("/confluence")
        if path == "/rest/api/space":
            names = {"ENG": "Engineering", "OPS": "Operations"}
            res = [{"id": 11 + i, "key": k, "name": names[k]} for i, k in enumerate(q.get("spaceKey", []))
                   if k in names]
            return h.send(200, {"results": res, "_links": {}})
        if path == "/rest/api/content/search":
            cql = q.get("cql", [""])[0]
            expand = q.get("expand", [""])[0]
            m = re.search(r"\bid in \(([0-9, ]+)\)", cql)
            if m:
                ids = {x.strip() for x in m.group(1).split(",")}
                matched = [p for p in PAGES if p[0] in ids]
            else:
                sm = re.search(r"space in \(([^)]*)\)", cql)
                spaces = set(re.findall(r'"([^"]+)"', sm.group(1))) if sm else set()
                one = re.search(r"\bid = ([0-9]+)", cql)
                matched = [p for p in PAGES if p[1] in spaces and (not one or p[0] == one.group(1))]
            matched.sort(key=lambda p: p[5])
            start = int(q.get("start", ["0"])[0] or 0)
            limit = int(q.get("limit", ["25"])[0] or 25)
            page = matched[start:start + limit]
            links = {"base": self.wiki_base}
            if start + limit < len(matched):
                links["next"] = "/confluence/rest/api/content/search?" + urllib.parse.urlencode(
                    {"cql": cql, "limit": limit, "start": start + limit, "expand": expand})
            return h.send(200, {"results": [self.page_json(p, expand) for p in page], "start": start,
                                "limit": limit, "size": len(page), "_links": links})
        m = re.match(r"^/rest/api/content/([0-9]+)(/restriction/byOperation/read)?$", path)
        if m:
            p = next((p for p in PAGES if p[0] == m.group(1)), None)
            if not p:
                return h.send(404, {"message": "no such page"})
            if m.group(2):
                return h.send(200, {"restrictions": self.restrictions()})
            return h.send(200, self.page_json(p, q.get("expand", [""])[0]))
        log(f"wiki: unanswered {method} {h.path}")
        return h.send(404, {"message": "not here"})

    def jira(self, h: Handler, method: str):
        u = urllib.parse.urlsplit(h.path)
        if h.headers.get("Authorization") != "Bearer " + self.jira_pat:
            return h.send(401, {"errorMessages": ["not signed in"]})
        if u.path != "/jira/rest/api/2/search" or method != "POST":
            log(f"jira: unanswered {method} {h.path}")
            return h.send(404, {"errorMessages": ["not here"]})
        req = json.loads(h.body() or b"{}")
        jql = req.get("jql", "")
        pm = re.search(r"project in \(([^)]*)\)", jql)
        keys = set(re.findall(r'"([^"]+)"', pm.group(1))) if pm else set()
        one = re.search(r"\bid = ([0-9]+)", jql)
        matched = [i for i in ISSUES if i[1].split("-")[0] in keys and (not one or i[0] == one.group(1))]
        start, limit = int(req.get("startAt") or 0), int(req.get("maxResults") or 50)
        out = []
        for iid, key, summary, desc, comment, status, itype, prio, labels, days in matched[start:start + limit]:
            comments = [{"id": iid + "1", "author": {"displayName": "Priya Raman"}, "body": comment,
                         "created": self.when(days, True)}] if comment else []
            proj = key.split("-")[0]
            out.append({"id": iid, "key": key, "fields": {
                "summary": summary, "description": desc,
                "comment": {"comments": comments, "total": len(comments), "startAt": 0},
                "status": {"name": status}, "issuetype": {"name": itype}, "priority": {"name": prio},
                "labels": labels, "security": None, "updated": self.when(days, True),
                "created": self.when(days + 6, True), "project": {"key": proj, "name": JIRA_PROJECTS[proj]}}})
        return h.send(200, {"startAt": start, "maxResults": limit, "total": len(matched), "issues": out})


def make_tls(work: str, ip: str) -> ssl.SSLContext:
    """A CA for the run and a leaf for ip, both under work; the context
    serving the leaf. The hub trusts work/ca.pem."""
    ca_key, ca = os.path.join(work, "ca.key"), os.path.join(work, "ca.pem")
    key, csr, leaf = (os.path.join(work, n) for n in ("leaf.key", "leaf.csr", "leaf.pem"))
    ext = os.path.join(work, "leaf.ext")
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca, "-days", "3",
            "-subj", "/CN=cloop demo recording CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=" + ip)
    with open(ext, "w") as fh:
        fh.write(f"subjectAltName=IP:{ip}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n"
                 "keyUsage=critical,digitalSignature,keyEncipherment\n")
    openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-out", leaf,
            "-days", "3", "-extfile", ext)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(leaf, key)
    return ctx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work", required=True, help="a directory for the run's keys and certificates")
    ap.add_argument("--projects-root", required=True, help="where the demo projects are")
    ap.add_argument("--private-ip", required=True, help="a private, non-loopback address of this machine")
    ap.add_argument("--ready", required=True, help="written with the services' addresses once they listen")
    args = ap.parse_args()

    idp = IdP(args.work)
    s_idp = serve("127.0.0.1", idp.route)
    idp.url = f"http://127.0.0.1:{s_idp.server_address[1]}"
    s_usage = serve("127.0.0.1", usage_route)
    s_msgs = serve("127.0.0.1", Messages(args.projects_root).route)
    tls = make_tls(args.work, args.private_ip)
    at = Atlassian()
    s_wiki = serve(args.private_ip, at.wiki, tls)
    s_jira = serve(args.private_ip, at.jira, tls)
    at.wiki_base = f"https://{args.private_ip}:{s_wiki.server_address[1]}/confluence"
    at.jira_base = f"https://{args.private_ip}:{s_jira.server_address[1]}/jira"

    ready = {"idp": idp.url, "usage": f"http://127.0.0.1:{s_usage.server_address[1]}/api/oauth/usage",
             "messages": f"http://127.0.0.1:{s_msgs.server_address[1]}/v1",
             "wiki": at.wiki_base, "jira": at.jira_base, "wiki_pat": at.wiki_pat, "jira_pat": at.jira_pat,
             "ca": os.path.join(args.work, "ca.pem")}
    tmp = args.ready + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(ready, fh)
    os.chmod(tmp, 0o600)
    os.rename(tmp, args.ready)
    log("listening: " + ", ".join(f"{k} {v}" for k, v in ready.items() if not k.endswith("_pat")))
    threading.Event().wait()
    return 0


if __name__ == "__main__":
    sys.exit(main())
