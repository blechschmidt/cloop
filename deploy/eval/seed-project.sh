#!/bin/sh
# Seed the evaluation stack with a project a remote executor can actually run.
#
# Run inside the executor image (which has git; the hub image deliberately does
# not) with both the gitrepos and the state volume mounted. See `make e2e-stack`.
#
# ── Why a git server at all ─────────────────────────────────────────────────
#
# A remote executor materialises a project by fetching it from an https URL. It
# has no access to the hub's filesystem — that is what makes it remote — so a
# project with no reachable origin cannot be dispatched to one at all: the hub
# refuses the run before it starts rather than letting a harness begin against
# an empty directory. Any end-to-end test of the remote path therefore needs a
# real origin, and this creates one: a bare repository served read-only over the
# proxy's TLS at https://cloop.localtest.me:8443/git/eval/project.git.
#
# Fetch-only is not a shortcut. It is the authority a sandbox should have over
# the source it was handed: read the tree, return work through the executor's
# own channel, never push to the origin.
#
# ── Why the mock provider ───────────────────────────────────────────────────
#
# The task the executor runs has to be a real one — a real decompose, a real
# task execution, real signal detection — without an API key or a network. The
# mock provider (pkg/provider/mock) matches prompts against a committed
# responses file, so the run is deterministic and free while every other layer
# is the production one.

set -eu

GIT_ROOT=${GIT_ROOT:-/srv/git}
STATE_ROOT=${STATE_ROOT:-/var/lib/cloop}
# The path has three segments deliberately. cloop matches a repository against
# grant allowlists as owner/name, so a two-segment URL is treated as a forge
# repository and refused without a grant — correctly, because for a forge repo a
# grant is the fix and the error can name it. A URL that is not owner/name (a
# GitLab subgroup, or this) takes the documented anonymous path instead: the
# fetch goes out unauthenticated, which is exactly right for a repository that
# needs no credential. Keeping the eval stack on that path is what lets it
# demonstrate the executor without also requiring an operator to mint a PAT for
# a server that ignores it.
ORIGIN=${ORIGIN:-https://cloop.localtest.me:8443/git/eval/project.git}
PROJECT_NAME=${PROJECT_NAME:-eval-project}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# A hermetic git: no ambient ~/.gitconfig, no signing, no hooks. The same
# reasoning as pkg/executor/gitprovision — a developer's global config must not
# be able to change what this produces.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=cloop-eval
export GIT_AUTHOR_EMAIL=eval@example.com
export GIT_COMMITTER_NAME=cloop-eval
export GIT_COMMITTER_EMAIL=eval@example.com

echo "seed: building the project tree"
mkdir -p "$WORK/src/.cloop"

# The marker is what the end-to-end assertion looks for on the *device*: a file
# that exists only in this repository, so finding it inside the executor's
# workspace proves the tree was fetched there rather than assumed.
cat > "$WORK/src/EVAL-MARKER" <<'MARKER'
cloop evaluation project. If you are reading this inside an executor's
workspace, the source tree was fetched from the origin rather than shared
from the hub's filesystem.
MARKER

cat > "$WORK/src/README.md" <<'README'
# cloop eval project

Seeded by `make e2e-stack`. One task, executed on a remote executor, against a
deterministic offline provider.
README

# Initialise through the real code path rather than hand-writing a state file:
# the on-disk shape is cloop's business and a fixture of it would drift.
echo "seed: cloop init"
(cd "$WORK/src" && HOME="$WORK" cloop init "Prove a remote executor can run a task" --provider mock >/dev/null)

# Written after init, because init writes a config of its own.
cat > "$WORK/src/.cloop/config.yaml" <<'CFG'
provider: mock
mock:
  responses_file: .cloop/mock_responses.yaml
CFG

# Two rules and a default, matched against substrings of cloop's real prompts.
# The decompose prompt asks for one exact JSON shape, so that rule has to
# return something ParseTaskPlan accepts; a task-execution prompt only needs a
# completion signal in its last few lines.
cat > "$WORK/src/.cloop/mock_responses.yaml" <<'RESPONSES'
rules:
  - substring: "produce a JSON task plan"
    response: |-
      {"tasks":[{"id":1,"title":"Confirm the workspace was materialised","description":"Read EVAL-MARKER from the fetched tree and report what it says.","priority":1,"role":"testing","depends_on":[],"time_estimate_minutes":1}]}
  - substring: "Confirm the workspace was materialised"
    response: |-
      Read EVAL-MARKER from the workspace. The tree was fetched, not assumed.
      CLOOP_E2E_TASK_EXECUTED
      TASK_DONE
default: |-
  CLOOP_E2E_TASK_EXECUTED
  TASK_DONE
RESPONSES

BARE="$GIT_ROOT/eval/project.git"
echo "seed: creating the bare origin at $BARE"
rm -rf "$BARE"
mkdir -p "$(dirname "$BARE")"
git init --quiet --bare --initial-branch=main "$BARE"

# SQLite's sidecar files are process state, not project state: committing them
# ships a write-ahead log that belongs to a database handle that no longer
# exists, which a clone then tries to replay.
rm -f "$WORK"/src/.cloop/*.db-wal "$WORK"/src/.cloop/*.db-shm

git -C "$WORK/src" init --quiet --initial-branch=main
git -C "$WORK/src" add -A
# --force because `cloop init` may write a .gitignore that excludes .cloop.
# Here the state and the mock responses ARE the project: the executor fetches
# this tree and runs against exactly what it finds.
git -C "$WORK/src" add --force .cloop
git -C "$WORK/src" commit --quiet -m "seed the cloop evaluation project"
git -C "$WORK/src" remote add origin "$BARE"
git -C "$WORK/src" push --quiet origin main

# What makes the dumb HTTP protocol work: without this index, a fetch over
# plain static file serving finds no refs and reports an empty repository.
git -C "$BARE" update-server-info
# nginx serves these as a different user than the one that wrote them.
chmod -R a+rX "$GIT_ROOT"

echo "seed: cloning into the hub's project directory"
HUB_PROJECT="$STATE_ROOT/projects/$PROJECT_NAME"
rm -rf "$HUB_PROJECT"
mkdir -p "$STATE_ROOT/projects"
git clone --quiet "$BARE" "$HUB_PROJECT"

# The origin the hub records must be the URL the *executor* will fetch from,
# not the local path this container cloned through. That URL is what ends up in
# the dispatched Spec, and a local path there is precisely the case the hub
# refuses ("a local path, not a URL the executor could fetch from").
git -C "$HUB_PROJECT" remote set-url origin "$ORIGIN"

echo "seed: registering the project with the hub"
mkdir -p "$STATE_ROOT/.cloop"
# The shape multiui.registry expects: an object with a "projects" key, not a
# bare array. A bare array is quarantined as corrupt on load and the hub starts
# with an empty registry, at which point project_idx=0 resolves to the hub's own
# working directory and the run is refused for the wrong reason.
cat > "$STATE_ROOT/.cloop/projects.json" <<REGISTRY
{
  "projects": [
    {"name": "$PROJECT_NAME", "path": "$HUB_PROJECT"}
  ]
}
REGISTRY

# No chown: this runs as the same uid the hub does (65532 in both images), so
# what it writes is already owned by the process that will read it. Running as
# root instead would not work — the executor service drops every capability, so
# a root process has no CAP_DAC_OVERRIDE and cannot write into a directory it
# does not own.

echo "seed: done — $PROJECT_NAME at $ORIGIN"
