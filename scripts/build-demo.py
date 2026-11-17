#!/usr/bin/env python3
"""build-demo.py — a static, read-only copy of the dashboard for the docs site.

The documentation site hosts the cloop dashboard at /demo/ so a reader can see
it without installing anything. That page is not a second UI written for the
purpose: a hand-written copy would drift from the real one with every change
to pkg/ui. It is the dashboard itself — the same index.html, stylesheet,
script bundle and deferred panels the hub embeds — copied out of pkg/ui/assets
at build time, plus three things the build adds:

  * website/demo/shim.js, loaded before any of the dashboard's own scripts. It
    stands in for the hub: it replaces fetch, XMLHttpRequest, WebSocket,
    EventSource and sendBeacon, answers reads from the fixtures below, refuses
    every write with a toast, and keeps the page from calling out — no sign-in
    redirect, Claude sign-in, telemetry or microphone.
  * website/demo/demo.css and website/demo/banner.html: a fixed banner saying
    this is a demo with canned data, with a link to the install guide.
  * the fixtures under website/demo/fixtures/, compiled into the shim's file so
    the page needs no request it could fail (see website/demo/README.md for
    their format).
  * the hub's own Content-Security-Policy, in a <meta>, since GitHub Pages
    sends none (CSP below).

The bundle is assembled the way pkg/ui/static.go assembles it: the fragments
of `bundleFiles` concatenated in order into one script, each of
`deferredScripts` served under its token, and every `{{asset:<token>}}` in
index.html replaced by that asset's URL. Those lists are read out of
static.go rather than repeated here, so a panel added to the dashboard joins
the demo with no edit to this file. Two differences from the hub, both
deliberate: assets keep their comments (the hub strips them in Go, and
re-implementing its strippers here would be a second thing to keep right), and
every URL is relative, because the site is served from /cloop/ and not from
the root of a hub.

Nothing here changes what the hub serves: pkg/ui/assets is only read, and the
shim never enters the binary.

    make docs-site     # the whole site, the demo in dist/docs-site/demo
    make docs-demo     # only the demo, into dist/docs-site/demo
    python3 scripts/build-demo.py --out /tmp/demo/demo   # anywhere else

Then serve the site directory and open /demo/:

    python3 -m http.server -d dist/docs-site 8000
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "pkg", "ui")
STATIC_GO = os.path.join(UI, "static.go")
DEMO_SRC = os.path.join(ROOT, "website", "demo")
FIXTURES_SRC = os.path.join(DEMO_SRC, "fixtures")
DEFAULT_OUT = os.path.join(ROOT, "dist", "docs-site", "demo")

# The install guide the banner links to, as a source page and as the URL
# mkdocs gives it (use_directory_urls), relative to the demo's index.html.
INSTALL_PAGE = "docs/getting-started/installation.md"
INSTALL_HREF = "../docs/getting-started/installation/"

# The hashed assets buildAssets() in static.go adds besides the deferred and
# page scripts: token -> file under pkg/ui. app.js is the bundle.
FIXED_ASSETS = {
    "app.css": "assets/app.css",
    "errboundary.js": "assets/js/errboundary.js",
    "chart.js": "assets/chart.umd.min.js",
}
# The icons index.html links from the hub's root. The demo carries them beside
# its other assets.
ICONS = ("icon-192.png", "apple-touch-icon.png", "icon.svg", "favicon.ico")

# What a fixture may say. See website/demo/README.md.
FIXTURE_METHODS = ("GET", "WS")
FIXTURE_KEYS = {"request", "status", "body", "text", "type", "frames", "note"}
# Query parameters a request carries that say nothing about what it asks for:
# the access token, cache busters and nonces. Dropped from a request's key, by
# the shim (VOLATILE in shim.js) as here, so a fixture does not have to know
# them. Keep the two lists the same.
VOLATILE_PARAMS = {"token", "_", "t", "ts", "nonce", "n", "cb"}

# The marker the demo's directory carries, so a rebuild only ever deletes a
# directory this script wrote.
MARKER = "demo.json"

# The Content-Security-Policy the hub sends with the dashboard
# (contentSecurityPolicy in pkg/ui/csp.go, on a hub without sign-in), which the
# dashboard is written to run under. GitHub Pages sends none, so the demo
# carries it in a <meta>, less the two directives a <meta> cannot carry and a
# browser complains about there: frame-ancestors and report-uri. It is what
# makes "nothing the page does leaves the site" the browser's rule as well as
# the shim's (connect-src, img-src and frame-src 'self'), and it keeps
# script-src 'self' on an origin the demo shares with every other Pages site
# of the account.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-src 'self'; "
       "base-uri 'none'; form-action 'self'; object-src 'none'")


class BuildError(Exception):
    pass


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def rel(path: str) -> str:
    return os.path.relpath(path, ROOT)


# ------------------------------------------------------------- static.go lists

def go_block(src: str, decl: str) -> str:
    """The body of a composite literal, from `decl` to its closing brace.

    The lists in static.go are flat literals whose closing brace starts a line,
    which is what gofmt makes of them. Line comments are dropped, since they
    quote file names that are not part of the list.
    """
    start = src.find(decl)
    if start < 0:
        raise BuildError(f"{rel(STATIC_GO)} no longer declares `{decl}` — teach "
                         "scripts/build-demo.py where the dashboard's asset lists went")
    end = src.find("\n}", start)
    if end < 0:
        raise BuildError(f"{rel(STATIC_GO)}: `{decl}` has no closing brace")
    body = src[start + len(decl):end]
    return "\n".join(line.split("//", 1)[0] for line in body.splitlines())


def static_lists() -> tuple[list[str], list[tuple[str, str]], list[tuple[str, str]]]:
    """bundleFiles, deferredScripts and pageScripts, as static.go lists them."""
    with open(STATIC_GO, encoding="utf-8") as fh:
        src = fh.read()
    bundle = re.findall(r'"([^"\\]+)"', go_block(src, "var bundleFiles = []string{"))
    pair = re.compile(r'\{\s*"([^"\\]+)"\s*,\s*"([^"\\]+)"\s*\}')
    deferred = pair.findall(go_block(src, "var deferredScripts = []struct{ token, path string }{"))
    page = pair.findall(go_block(src, "var pageScripts = []struct{ token, path string }{"))
    if not bundle or not deferred or not page:
        raise BuildError(f"read no {'bundleFiles' if not bundle else 'deferredScripts' if not deferred else 'pageScripts'} "
                         f"entries out of {rel(STATIC_GO)} — has the list changed shape?")
    return bundle, deferred, page


def check_bundle(bundle: list[str]) -> None:
    """The bundle covers every fragment, once, in filename order.

    The same promise TestStaticAssets_BundleCoversEveryFragment makes about the
    hub. Checked again here because this script reads the list by pattern: a
    fragment it failed to read would leave a hole in the demo's script with no
    error anywhere.
    """
    js = os.path.join(UI, "assets", "js")
    on_disk = sorted(f"assets/js/{n}" for n in os.listdir(js)
                     if n.endswith(".js") and n != "errboundary.js"
                     and os.path.isfile(os.path.join(js, n)))
    if len(set(bundle)) != len(bundle):
        raise BuildError(f"bundleFiles in {rel(STATIC_GO)} lists a fragment twice")
    if bundle != on_disk:
        missing = sorted(set(on_disk) - set(bundle))
        extra = sorted(set(bundle) - set(on_disk))
        raise BuildError("the bundle read out of static.go is not the fragments in "
                         f"pkg/ui/assets/js (unread: {missing or 'none'}; not on disk: "
                         f"{extra or 'none'}; or out of order) — is static.go's list in a "
                         "shape go_block() does not read?")


# ------------------------------------------------------------------- fixtures

def normalise(request: str, where: str) -> str:
    """A fixture's request line in the form the shim keys requests by.

    `GET /api/state?project_idx=0` — the method, the path, and the query with
    the volatile parameters dropped and the rest sorted. A query of `*`, or one
    ending in `&*`, matches any further parameters (shim.js, wildcard).
    """
    method, sep, target = request.strip().partition(" ")
    target = target.strip()
    if not sep or method not in FIXTURE_METHODS:
        raise BuildError(f"{where}: request {request!r} must be '<{'|'.join(FIXTURE_METHODS)}> /path[?query]'")
    if not target.startswith("/") or target.startswith("//"):
        raise BuildError(f"{where}: request {request!r} must name a path that starts with one '/'")
    path, _, query = target.partition("?")
    params = urllib.parse.parse_qsl(query, keep_blank_values=True)
    wild = any(k == "*" for k, _ in params)
    kept = sorted((k, v) for k, v in params if k != "*" and k not in VOLATILE_PARAMS)
    q = "&".join(urllib.parse.quote(k, safe="-_.!~*'()") + "=" +
                 urllib.parse.quote(v, safe="-_.!~*'()") for k, v in kept)
    if wild:
        q = q + "&*" if q else "*"
    return f"{method} {path}" + (f"?{q}" if q else "")


def load_fixtures() -> list[dict]:
    """Every fixture under website/demo/fixtures, checked."""
    fixtures: list[dict] = []
    places: list[str] = []
    seen: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(FIXTURES_SRC):
        dirnames.sort()
        for name in sorted(filenames):
            if not name.endswith(".json"):
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError) as err:
                raise BuildError(f"{rel(path)}: {err}") from err
            entries = doc if isinstance(doc, list) else [doc]
            for i, fx in enumerate(entries):
                where = rel(path) + (f"[{i}]" if isinstance(doc, list) else "")
                if not isinstance(fx, dict) or not isinstance(fx.get("request"), str):
                    raise BuildError(f"{where}: a fixture is an object with a 'request' line")
                unknown = sorted(set(fx) - FIXTURE_KEYS)
                if unknown:
                    raise BuildError(f"{where}: unknown field(s) {unknown}; a fixture may say "
                                     f"{sorted(FIXTURE_KEYS)}")
                key = normalise(fx["request"], where)
                if key in seen:
                    raise BuildError(f"{where}: {key!r} is already answered by {seen[key]}")
                seen[key] = where
                out = {"request": key}
                if key.startswith("WS "):
                    frames = fx.get("frames")
                    if not isinstance(frames, list) or set(fx) - {"request", "frames", "note"}:
                        raise BuildError(f"{where}: a WS fixture has 'frames', a list of the "
                                         "messages the socket sends, and nothing else")
                    out["frames"] = frames
                else:
                    if ("body" in fx) == ("text" in fx):
                        raise BuildError(f"{where}: a GET fixture has a JSON 'body' or a 'text' body, one of the two")
                    if "frames" in fx:
                        raise BuildError(f"{where}: 'frames' belongs to a WS fixture")
                    status = fx.get("status", 200)
                    if not isinstance(status, int) or not 200 <= status <= 599 or status in (401, 403):
                        raise BuildError(f"{where}: status {status!r} must be an HTTP status from 200 "
                                         "to 599 and not 401 or 403, which would send the page to sign in")
                    if "text" in fx and not isinstance(fx["text"], str):
                        raise BuildError(f"{where}: 'text' must be a string")
                    if "type" in fx and not isinstance(fx["type"], str):
                        raise BuildError(f"{where}: 'type' must be a media type string")
                    out.update({k: fx[k] for k in ("status", "body", "text", "type") if k in fx})
                fixtures.append(out)
                places.append(where)
    return resolve_refs(fixtures, places)


def resolve_refs(fixtures: list[dict], places: list[str]) -> list[dict]:
    """Replace each {"$fixture": "GET …"} with that fixture's JSON body.

    The hub says some things more than once — the state document a project's
    socket opens with is GET /api/state's answer, and a task's details carry
    the task as the state lists it — so a fixture can name another instead of
    repeating it, and "at" (a JSON pointer, RFC 6901) picks a part of it:
    {"$fixture": "GET /api/state?project_idx=0", "at": "/plan/tasks/0"}.
    Resolved here, so the shim never sees a reference.
    """
    by_key = {fx["request"]: fx for fx in fixtures}

    def pointer(doc, at: str, where: str):
        if at == "":
            return doc
        if not at.startswith("/"):
            raise BuildError(f"{where}: 'at' {at!r} must be a JSON pointer starting with '/'")
        for part in at[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(doc, dict) and part in doc:
                doc = doc[part]
            elif isinstance(doc, list) and part.isdigit() and int(part) < len(doc):
                doc = doc[int(part)]
            else:
                raise BuildError(f"{where}: 'at' {at!r} names nothing in the fixture it points into")
        return doc

    def resolve(value, where: str, stack: tuple):
        if isinstance(value, list):
            return [resolve(v, where, stack) for v in value]
        if not isinstance(value, dict):
            return value
        if "$fixture" not in value:
            return {k: resolve(v, where, stack) for k, v in value.items()}
        ref, at = value["$fixture"], value.get("at", "")
        if set(value) - {"$fixture", "at"} or not isinstance(at, str):
            raise BuildError(f"{where}: a reference is {{\"$fixture\": \"GET …\"}}, with an optional "
                             "\"at\" pointer, and nothing else")
        key = normalise(ref, where) if isinstance(ref, str) else None
        target = by_key.get(key)
        if target is None or "body" not in target:
            raise BuildError(f"{where}: $fixture {ref!r} names no GET fixture with a JSON body")
        if key in stack:
            raise BuildError(f"{where}: $fixture {ref!r} refers to itself through {' -> '.join(stack)}")
        return resolve(copy.deepcopy(pointer(target["body"], at, where)), where, stack + (key,))

    return [resolve(fx, where, (fx["request"],)) for fx, where in zip(fixtures, places)]


# --------------------------------------------------------------------- output

def hashed_name(stem: str, ext: str, body: bytes) -> str:
    """assets/<stem>.<hash>.<ext>, the hash being static.go's contentHash.

    GitHub Pages lets browsers cache for ten minutes, so a name that changes
    with the bytes keeps a reader from running one deploy's bundle against
    another's stylesheet or shim.
    """
    return f"assets/{stem}.{hashlib.sha256(body).hexdigest()[:16]}.{ext}"


def git_commit() -> str | None:
    try:
        out = subprocess.run(["git", "-C", ROOT, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
                             check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return out or None


def prepare_out(out: str) -> None:
    """Empty the output directory — only if it is one this script wrote."""
    if os.path.lexists(out):
        if not os.path.isdir(out) or os.path.islink(out):
            raise BuildError(f"{out} exists and is not a directory")
        if os.listdir(out) and not os.path.isfile(os.path.join(out, MARKER)):
            raise BuildError(f"{out} is not empty and has no {MARKER}, so it was not "
                             "written by this script; refusing to delete it")
        shutil.rmtree(out)
    os.makedirs(out)


def build(out: str) -> dict:
    bundle, deferred, page = static_lists()
    check_bundle(bundle)

    index = read_bytes(os.path.join(UI, "assets", "index.html")).decode("utf-8")
    sources: dict[str, tuple[str, str, bytes]] = {}   # token -> (stem, ext, bytes)
    sources["app.js"] = ("app", "js", b"".join(read_bytes(os.path.join(UI, f)) for f in bundle))
    for token, path in list(FIXED_ASSETS.items()) + deferred + page:
        stem, _, ext = token.rpartition(".")
        full = os.path.join(UI, path)
        if not os.path.isfile(full):
            raise BuildError(f"{rel(STATIC_GO)} names {path} for {token}, which does not exist")
        sources[token] = (stem, ext, read_bytes(full))

    # Only what index.html names: the glasses and device pages' scripts are
    # page scripts too, of pages the demo does not carry.
    files: dict[str, bytes] = {}
    used = set(re.findall(r"\{\{asset:([^}]+)\}\}", index))
    unknown = sorted(used - set(sources))
    if unknown:
        raise BuildError(f"pkg/ui/assets/index.html names asset(s) {unknown} that static.go "
                         "does not serve — has buildAssets() gained one this script does not know?")
    for token in sorted(used):
        stem, ext, body = sources[token]
        name = hashed_name(stem, ext, body)
        files[name] = body
        index = index.replace("{{asset:" + token + "}}", name)

    for icon in ICONS:
        files["assets/" + icon] = read_bytes(os.path.join(UI, "assets", icon))
        index, n = re.subn(r'href="/' + re.escape(icon) + '"', f'href="assets/{icon}"', index)
        if n != 1:
            raise BuildError(f"index.html links /{icon} {n} times, expected once")
    # The web app manifest describes the hub at its root; the demo is not an
    # installable app, and its icons would 404 from here.
    index, n = re.subn(r'\s*<link rel="manifest"[^>]*>', "", index)
    if n != 1:
        raise BuildError(f"index.html has {n} manifest links, expected one")

    # What the demo adds: the shim with its fixtures, the banner and its
    # stylesheet, and the policy.
    shim_src = read_bytes(os.path.join(DEMO_SRC, "shim.js"))
    fixtures = load_fixtures()
    prelude = ("// Generated by scripts/build-demo.py from website/demo/fixtures; the shim "
               "below reads and removes it.\n"
               "window.__cloopDemoFixtures = " +
               json.dumps({"version": 1, "fixtures": fixtures}, separators=(",", ":"), ensure_ascii=False) +
               ";\n").encode("utf-8")
    shim = prelude + shim_src
    shim_name = hashed_name("shim", "js", shim)
    files[shim_name] = shim
    css = read_bytes(os.path.join(DEMO_SRC, "demo.css"))
    css_name = hashed_name("demo", "css", css)
    files[css_name] = css
    banner = read_bytes(os.path.join(DEMO_SRC, "banner.html")).decode("utf-8").strip()
    if 'href="{{install}}"' not in banner:
        raise BuildError("website/demo/banner.html must link the install guide as href=\"{{install}}\"")
    if not os.path.isfile(os.path.join(ROOT, INSTALL_PAGE)):
        raise BuildError(f"the banner links the install guide, {INSTALL_PAGE}, which no longer exists")
    banner = banner.replace("{{install}}", INSTALL_HREF)

    # The policy before anything it governs: right after the charset, the
    # first thing in the head.
    charset = re.search(r'<meta charset="[^"]*">', index)
    if not charset or charset.start() > index.find("</head>"):
        raise BuildError("index.html has no <meta charset> in its head to put the policy after")
    index = (index[:charset.end()] + f'\n<meta http-equiv="Content-Security-Policy" content="{CSP}">' +
             index[charset.end():])

    # The shim first: before theme.js, the head's first script, so nothing the
    # dashboard runs ever sees the real fetch or WebSocket.
    first_script = index.find("<script")
    if first_script < 0 or first_script > index.find("</head>"):
        raise BuildError("index.html has no script in its head to put the shim before")
    index = index[:first_script] + f'<script src="{shim_name}"></script>\n' + index[first_script:]
    css_link = re.search(r'<link rel="stylesheet" href="assets/app\.[0-9a-f]{16}\.css">', index)
    if not css_link:
        raise BuildError("index.html links no app.css to put the demo's stylesheet after")
    index = index[:css_link.end()] + f'\n<link rel="stylesheet" href="{css_name}">' + index[css_link.end():]
    body = re.search(r"<body[^>]*>", index)
    if not body:
        raise BuildError("index.html has no <body>")
    index = index[:body.end()] + "\n" + banner + "\n" + index[body.end():]

    # What is left must all resolve inside the demo: the hub's own root is not
    # there to answer an absolute path, and on github.io it is someone else's.
    for attr, target in re.findall(r'\b(href|src|content)="([^"]*)"', index):
        if attr == "content" and not target.startswith("assets/"):
            continue
        if target.startswith(("/", "{{")) or ("://" in target and attr != "href"):
            raise BuildError(f"index.html still has {attr}=\"{target}\", which the demo cannot serve")
        if target.startswith("assets/") and target not in files:
            raise BuildError(f"index.html names {target}, which the build did not write")

    files["index.html"] = index.encode("utf-8")
    stamp = {
        "format": 1,
        "commit": git_commit(),
        "fixtures": len(fixtures),
        "bundle": [posixpath.basename(f) for f in bundle],
        "assets": sorted(files),
    }
    files[MARKER] = (json.dumps(stamp, indent=2) + "\n").encode("utf-8")

    prepare_out(out)
    for name, data in files.items():
        target = os.path.join(out, name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
    return {"fixtures": len(fixtures), "files": len(files),
            "bytes": sum(len(b) for b in files.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="directory to write the demo into (default: dist/docs-site/demo)")
    args = parser.parse_args()
    out = os.path.abspath(args.out)
    try:
        result = build(out)
    except BuildError as err:
        print(f"build-demo: {err}", file=sys.stderr)
        return 1
    # With the site built, the banner's link must land on a page of it.
    site = os.path.dirname(out)
    install = os.path.normpath(os.path.join(out, INSTALL_HREF, "index.html"))
    if os.path.isfile(os.path.join(site, "index.html")) and not os.path.isfile(install):
        print(f"build-demo: the banner links {INSTALL_HREF}, which the site in {rel(site)} does not have",
              file=sys.stderr)
        return 1
    print(f"build-demo: wrote {result['files']} files ({result['bytes'] // 1024} KiB, "
          f"{result['fixtures']} fixtures) into {rel(out) if out.startswith(ROOT) else out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
