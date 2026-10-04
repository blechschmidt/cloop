#!/usr/bin/env python3
r"""Choose which edge-release assets to delete (Task 20376).

The "edge" prerelease accumulates twelve assets per commit on main (five
archives, the manifest, and a signature bundle for each), and GitHub caps a
release at a thousand. More to the point, a build from months ago is not
something the Upgrade dialog should be able to send a device to: the edge
channel is "follow the hub", and a hub that old wants a release. So edge.yml
keeps the builds of the newest --keep commits and deletes the rest.

"Newest" is by position in main's history (`git rev-list origin/main`, newest
first), not by upload time: re-running an old commit's workflow must not make it
the newest build. An asset whose commit is not on main at all is deleted
whatever --keep says — edge.yml only builds commits on main, so such an asset
was not put there by it. An asset whose name carries no commit is left alone:
this script deletes only what it can account for.

Input:
  --assets FILE   one asset per line, "<id> <name>" (what
                  `gh api --paginate .../assets --jq '.[] | "\(.id) \(.name)"'` prints)
  --history FILE  one commit id per line, newest first
  --keep N        how many commits' builds to keep (default 30)

Output: one line per asset to delete, "<id> <name>", for the workflow to feed to
`gh api -X DELETE`. Nothing is deleted here.
"""

import argparse
import re
import sys

ASSET = re.compile(r"^cloop_([0-9a-f]{40})_")


def plan(assets, history, keep):
    """Return the assets to delete, as (id, name) pairs in input order."""
    rank = {c: i for i, c in enumerate(history)}
    commits = {}
    for a in assets:
        m = ASSET.match(a["name"])
        if m:
            commits.setdefault(m.group(1), []).append(a)
    on_main = sorted((c for c in commits if c in rank), key=lambda c: rank[c])
    kept = set(on_main[:keep])
    doomed = []
    for a in assets:
        m = ASSET.match(a["name"])
        if m and m.group(1) not in kept:
            doomed.append((a["id"], a["name"]))
    return doomed


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--assets", required=True)
    ap.add_argument("--history", required=True)
    ap.add_argument("--keep", type=int, default=30)
    args = ap.parse_args()
    if args.keep < 1:
        sys.exit("edge-prune: --keep must be at least 1; the newest build is the one the hub runs")
    assets = []
    with open(args.assets) as f:
        for line in f:
            asset_id, _, name = line.strip().partition(" ")
            if asset_id and name:
                assets.append({"id": asset_id, "name": name})
    with open(args.history) as f:
        history = [line.strip() for line in f if line.strip()]
    for asset_id, name in plan(assets, history, args.keep):
        print(asset_id, name)


if __name__ == "__main__":
    main()
