#!/usr/bin/env python3
"""build-docs.py — assemble the MkDocs source tree for the documentation site.

The guides live where contributors and GitHub expect them: `docs/`, split into
topic sections, plus `README.md` at the repository root. The published site must
not fork that tree into a second copy that rots, so this script publishes the
repository's own Markdown rather than a copy of it.

It stages the files into `dist/docs-src/`, *mirroring the repository layout* so
every relative link between them keeps resolving untouched, and rewrites only
what cannot survive the move:

  * links to things the site does not carry (Go packages, Helm charts, test
    directories, YAML configs) become links to that file on GitHub;
  * links to a directory that has a `README.md` become links to that README,
    since a static site cannot serve a directory listing;
  * the project README is staged as `overview.md` — `index.md` is the site's
    landing page — and links that pointed at it are retargeted.

The navigation is derived from `docs/README.md`: its `##` headings give the
section order and its links give each section's pages, in order, with the
curated link text as the menu label. A page joins the site's menu the moment it
is listed there, and there is no third list to keep in sync. `check-docs.sh`
enforces the other direction — that every page under `docs/` is listed — so the
two together make the map exhaustive. Anything found under `docs/` but missing
from the map is still published, appended to a trailing section rather than
silently dropped, and reported.

Output: `dist/mkdocs.yml` + `dist/docs-src/`, ready for `mkdocs build`.
Run it through `make docs-site` (build) or `make docs-serve` (live preview).
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
SRC = os.path.join(DIST, "docs-src")
OUT_CONFIG = os.path.join(DIST, "mkdocs.yml")
BASE_CONFIG = os.path.join(ROOT, "website", "mkdocs.yml")

REPO_URL = "https://github.com/blechschmidt/cloop"
# The branch off-site links point at. Overridable so a fork or a release branch
# can publish links into its own tree.
REF = os.environ.get("DOCS_REF", "main")

# Inline links, optionally with a "title", and reference-style definitions.
LINK_RE = re.compile(r'(?P<open>\]\(\s*)(?P<target>[^)\s]+)(?P<rest>\s*(?:"[^"]*")?\s*\))')
REFDEF_RE = re.compile(r'(?P<open>^\s*\[[^\]]+\]:\s*)(?P<target>\S+)', re.M)
EXTERNAL_RE = re.compile(r'^(?:[a-z][a-z0-9+.-]*:|//|#)')
FENCE_RE = re.compile(r'^\s*(?:```|~~~)')

# Pages that are not part of a docs/ section, staged at the site root.
ROOT_PAGES = [("Project overview", "README.md", "overview.md")]
# Pages written for the site rather than imported from the repository. Their
# links are authored against the position they are staged at, not the folder
# they are stored in.
SITE_AUTHORED = {"website/index.md"}
# Sections of docs/README.md that are prose about the repository rather than a
# list of site pages. They link to source directories, not documentation.
SKIP_SECTIONS = {"elsewhere in the repository"}
# Non-Markdown files under docs/ that pages embed and the site must carry.
ASSET_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp")

warnings: list[str] = []


def warn(message: str) -> None:
    warnings.append(message)


def read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def link_targets(text: str) -> list[tuple[str, str]]:
    """(link text, target) for every inline link, in document order."""
    return re.findall(r'\[([^\]]*)\]\(\s*([^)\s]+)', text)


def clean_title(text: str) -> str:
    """Link text -> nav label: drop emphasis, code ticks and stray whitespace."""
    text = re.sub(r'`([^`]*)`', r'\1', text)
    text = re.sub(r'\*+', '', text)
    return re.sub(r'\s+', ' ', text).strip()


def heading_of(repo_rel: str) -> str:
    for line in read(os.path.join(ROOT, repo_rel)).splitlines():
        if line.startswith("# "):
            return clean_title(line[2:])
    return posixpath.basename(repo_rel)


# --------------------------------------------------------------- staging map

def staged_files() -> tuple[dict[str, str], list[str]]:
    """(repo-relative source -> site-relative destination, binary assets)."""
    staged: dict[str, str] = {}
    assets: list[str] = []

    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "docs")):
        dirnames.sort()
        for name in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
            if name.endswith(".md"):
                staged[rel] = rel
            elif name.lower().endswith(ASSET_SUFFIXES):
                assets.append(rel)

    for _, source, dest in ROOT_PAGES:
        staged[source] = dest

    staged["website/index.md"] = "index.md"
    return staged, assets


# ------------------------------------------------------------ link rewriting

class Rewriter:
    def __init__(self, staged: dict[str, str], assets: list[str]):
        # Assets keep their repository path on the site, so a link to one
        # resolves exactly as it did on GitHub.
        self.staged = dict(staged)
        self.staged.update({a: a for a in assets})
        self.to_github = 0
        self.retargeted = 0
        self.missing = 0

    def target(self, target: str, orig_dir: str, staged_dir: str) -> str:
        path, sep, anchor = target.partition("#")
        if not path:
            return target                                   # same-page anchor

        resolved = posixpath.normpath(posixpath.join(orig_dir, path))
        if resolved.startswith(".."):                       # escapes the repo
            return target

        dest = self.staged.get(resolved)
        if dest is None and os.path.isdir(os.path.join(ROOT, resolved)):
            # A static site cannot serve a directory; use its README instead.
            dest = self.staged.get(posixpath.join(resolved, "README.md"))

        if dest is not None:
            new = posixpath.relpath(dest, staged_dir) if staged_dir else dest
            if new != path:
                self.retargeted += 1
            return new + sep + anchor

        absolute = os.path.join(ROOT, resolved)
        if not os.path.exists(absolute):
            self.missing += 1
            warn(f"link target does not exist: {orig_dir or '.'} -> {target}")
            return target
        # Off-site: source code, charts, tests, configs. Send readers to the
        # file on GitHub rather than 404 on a page the site does not carry. Any
        # anchor rides along — GitHub understands #L42 on a blob.
        self.to_github += 1
        kind = "tree" if os.path.isdir(absolute) else "blob"
        return f"{REPO_URL}/{kind}/{REF}/{resolved}" + sep + anchor

    def text(self, text: str, orig_rel: str, staged_rel: str) -> str:
        staged_dir = posixpath.dirname(staged_rel)
        orig_dir = staged_dir if orig_rel in SITE_AUTHORED else posixpath.dirname(orig_rel)

        def replace(match: re.Match) -> str:
            target = match.group("target")
            if EXTERNAL_RE.match(target):
                return match.group(0)
            stripped = target.strip("<>")
            rewritten = self.target(stripped, orig_dir, staged_dir)
            if rewritten == stripped:
                return match.group(0)
            if target.startswith("<"):
                rewritten = f"<{rewritten}>"
            return match.group(0).replace(target, rewritten, 1)

        # Rewrite outside fenced blocks only: a link inside a code sample is
        # sample text, not navigation.
        out, fenced = [], False
        for line in text.splitlines(keepends=True):
            if FENCE_RE.match(line):
                fenced = not fenced
            elif not fenced:
                line = LINK_RE.sub(replace, line)
                line = REFDEF_RE.sub(replace, line)
            out.append(line)
        return "".join(out)


# ------------------------------------------------------------------ nav tree

def map_sections(docs_map: str) -> list[tuple[str, str]]:
    """(section title, section body) for each '## ' heading of docs/README.md."""
    parts = re.split(r'^##\s+(.+?)\s*$', docs_map, flags=re.M)[1:]
    return [(parts[i].strip(), parts[i + 1]) for i in range(0, len(parts), 2)]


def build_nav(staged: dict[str, str]) -> list:
    """Derive the site navigation from docs/README.md."""
    docs_map = read(os.path.join(ROOT, "docs", "README.md"))
    sections = map_sections(docs_map)
    if not sections:
        sys.exit("build-docs: no '##' sections in docs/README.md — has the map format changed?")

    nav: list = [{"Home": "index.md"}]
    for title, _, dest in ROOT_PAGES:
        nav.append({title: dest})
    nav.append({"Documentation map": "docs/README.md"})

    covered = {"docs/README.md"}
    for title, body in sections:
        if title.strip().lower() in SKIP_SECTIONS:
            continue
        entries: list = []
        for text, target in link_targets(body):
            target = target.split("#")[0]
            if not target.endswith(".md"):
                continue
            page = posixpath.normpath(posixpath.join("docs", target))
            if page not in staged or page in covered:
                continue
            covered.add(page)
            # A section index is the section's own landing page, which
            # navigation.indexes renders as the clickable parent.
            if page.endswith("/README.md") and not entries:
                entries.append(page)
            else:
                entries.append({clean_title(text) or heading_of(page): page})
        if entries:
            nav.append({clean_title(title): entries})
        else:
            warn(f"section '{title}' of docs/README.md lists no site pages — skipped")

    # check-docs.sh requires every page to be listed; if one slips through
    # anyway, publish it rather than lose it.
    orphans = sorted(p for p in staged
                     if p.startswith("docs/") and p not in covered)
    if orphans:
        extra: list = []
        for page in orphans:
            warn(f"{page} is not listed in docs/README.md — appended to the nav")
            extra.append({heading_of(page): page})
        nav.append({"Unlisted": extra})

    return nav


def dump_nav(nav: list, indent: int = 2) -> str:
    """Minimal YAML writer: nav entries are strings or single-key mappings."""
    lines = []

    def emit(items: list, level: int) -> None:
        pad = " " * (indent * level)
        for item in items:
            if isinstance(item, str):
                lines.append(f"{pad}- {item}")
                continue
            (key, value), = item.items()
            if isinstance(value, str):
                lines.append(f"{pad}- {json.dumps(key)}: {value}")
            else:
                lines.append(f"{pad}- {json.dumps(key)}:")
                emit(value, level + 2)

    lines.append("nav:")
    emit(nav, 1)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------- main

def main() -> int:
    if not os.path.exists(BASE_CONFIG):
        sys.exit(f"build-docs: missing base config {BASE_CONFIG}")
    base = read(BASE_CONFIG)
    if re.search(r'^nav:', base, re.M):
        sys.exit("build-docs: website/mkdocs.yml must not define nav: — it is generated here")

    staged, assets = staged_files()
    nav = build_nav(staged)

    if os.path.exists(SRC):
        shutil.rmtree(SRC)
    os.makedirs(SRC)

    rewriter = Rewriter(staged, assets)
    for source, dest in sorted(staged.items()):
        target = os.path.join(SRC, dest)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(rewriter.text(read(os.path.join(ROOT, source)), source, dest))

    for asset in assets:
        target = os.path.join(SRC, asset)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, asset), target)

    shutil.copytree(os.path.join(ROOT, "website", "assets"), os.path.join(SRC, "assets"))

    with open(OUT_CONFIG, "w", encoding="utf-8") as fh:
        fh.write("# GENERATED by scripts/build-docs.py — edit website/mkdocs.yml instead.\n")
        fh.write(base.rstrip("\n") + "\n\n")
        fh.write("# Derived from the sections and links of docs/README.md.\n")
        fh.write(dump_nav(nav))

    for message in warnings:
        print(f"build-docs: warning: {message}", file=sys.stderr)

    print(f"build-docs: staged {len(staged)} pages and {len(assets)} assets into "
          f"{os.path.relpath(SRC, ROOT)} ({rewriter.retargeted} links retargeted, "
          f"{rewriter.to_github} pointed at GitHub, {len(nav)} nav sections) "
          f"-> {os.path.relpath(OUT_CONFIG, ROOT)}")
    return 1 if rewriter.missing else 0


if __name__ == "__main__":
    sys.exit(main())
