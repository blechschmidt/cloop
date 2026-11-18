# Recording the demo's fixtures

The dashboard demo on the documentation site (`/demo/`, see
[website/demo/README.md](../../website/demo/README.md)) answers every read
from the fixtures in `website/demo/fixtures`. This directory holds the
scripts that record those fixtures from a real hub, so the demo shows what
cloop actually draws.

```bash
scripts/demo/record-fixtures.sh            # record and write website/demo/fixtures
KEEP=1 scripts/demo/record-fixtures.sh     # keep the scratch directory afterwards
OUT=/tmp/try scripts/demo/record-fixtures.sh   # write somewhere else first
make docs-demo                             # then build the demo from the fixtures
```

It takes about fifteen minutes, needs root (for a PID namespace, below), Go,
git, Python 3.10 or later, Node 22 or later, openssl, curl, a Chrome or
Chromium (set `CHROME` if it is not at `/opt/cft/chrome-linux64/chrome` or on
PATH) and about 3 GB free under `/tmp`. When it finishes it has also built the
demo from the new fixtures, walked every tab of it, and run `tests/demo` on
them. Read its last lines before committing.

## What it records

Three small projects, made up for the demo (`projects.py`):

| Project | What happens to it |
| --- | --- |
| `todo-api` | A Go REST service. Five tasks and a human review gate, all done. The gate is approved by Dana between the tests and the README. The test task attaches a coverage report and a chart. Two requirements, checked. |
| `landing-page` | A static site. Requirements R-1 to R-4, linked to the tasks that implement them, checked, with a red-green proof of R-1 and a traceability matrix. Its link check fails, is diagnosed, and passes when retried. A parallel feature, `dark-mode`, has its own task list and run. A task added after the launch is still pending. It runs on the Anthropic API provider, so it has token usage and costs. |
| `csv-report` | A Python script. The first task is done, then the run pauses because the Claude usage limit was reached, with three tasks still pending. Two requirements, one met and one not yet. |

Each project is a git repository whose commits the runs make. The runs go
through the hub (`POST /api/run`), so the event history, step logs, costs,
timeline, analytics, provider calls and each task's activity come from cloop
itself.

Around them, everything is seeded through the hub's own API: an edge device
with labels, a sandbox, a firewall and limits; a virtual executor with
firewall rules and a USB device; a container executor; an executor pool whose
controller has checked in; secrets of several kinds and grants to projects,
labels and executors; an access request waiting in the approvals inbox and an
approved one; a Confluence and a Jira knowledge source, synced and bound;
readers, teams, shares, API tokens, quotas, budget caps, Claude caps, a legal
hold, a SCIM credential, a CI rule, and the hub's notification, speech and
disk settings. The audit trail and hub health are whatever all that produced.

The viewer is Dana Whitfield, signed in through single sign-on, an
administrator who is also in the group of every other role. She also does the
seeding, starts the runs and approves the gate and Priya's earlier request,
so the audit trail and the records name a person. Priya Raman (operator) and
Sam Okafor (viewer) are signed in too, so sessions, shares and requests have
more than one person in them. Only the executor pool, its controller's report
and the device's enrollment use the hub's static token.

## How it works

`record-fixtures.sh` runs these steps in a fresh directory under `/tmp`:

1. Starts `fakes.py`: an OpenID Connect provider that signs in whoever it is
   told to, Claude's usage endpoint, the Anthropic Messages API, and
   Confluence and Jira Data Center over TLS on a private address of the
   machine (the knowledge connectors refuse loopback), with a CA made for the
   run.
2. Builds cloop from this tree with one difference: it asks the fake usage
   endpoint instead of `api.anthropic.com`
   (`-X …/pkg/ratelimit.usageEndpoint=…`).
3. Creates the projects (`recorder.py setup`): files, a first commit,
   `cloop init`, `cloop plan import`, the review gate.
4. Starts the hub in `todo-api` with single sign-on and a role policy (the
   overlay `.cloop/config.ui-<port>.yaml`), `--listen 127.0.0.1` and a token,
   with the other two projects as `--projects`.
5. Enrolls the edge device (`recorder.py agent`): a script that speaks the
   agent protocol, with an invented machine and USB devices, and answers the
   hub's isolation probes.
6. Seeds the admin surfaces (`recorder.py seed`) and runs the projects
   (`recorder.py runs`). Claude Code is `stub-claude.py`, first on the hub's
   PATH; it does what `projects.py` says each task's turn does: writes the
   files and commits them, attaches files, fails once, or prints Claude Code's
   usage-limit message.
7. Walks the real dashboard in headless Chrome as Dana (`walk.js record`):
   every project tab for each project, every hub tab, each task's details.
   Every GET answer and each socket's opening frames are kept.
8. Fetches every other read the dashboard can make (`recorder.py crawl`):
   the GET routes in the hub's route table (`/api/openapi.json`) that the
   dashboard's scripts name, for every project, task, executor, grant and
   other thing each route takes. A route the walk did not reach is saved
   with a wildcard query (`?project_idx=0&*`), so it answers whatever the
   dashboard adds.
9. Scrubs it all and writes the fixtures (`recorder.py write`), one file per
   project and route group. A read whose query carries a date the dashboard
   computed from the day it was opened (Analytics asks for the last 30 days)
   also gets a wildcard twin, so it is answered on any later day.
10. Builds the demo from them, serves it, walks it again (`walk.js check`),
    runs `tests/demo` on the recording, and removes the scratch directory.
    `tests/demo` includes the browser sweep, which walks the demo once more
    at a phone, a tablet and a desktop width, opens the admin dialogs and
    presses three buttons that would write
    ([website/demo/README.md](../../website/demo/README.md) has the details).

To check a demo as a reader meets it weeks later, run the check walk with the
page's clock moved ahead:

```bash
python3 scripts/build-demo.py --out /tmp/site/demo
python3 -m http.server -d /tmp/site --bind 127.0.0.1 8000 &
WALK_DAYS_LATER=60 node scripts/demo/walk.js check "$CHROME" http://127.0.0.1:8000/demo projects.json report.json
```

`projects.json` lists the three projects as the fixtures show them, for
example `{"name": "todo-api", "path": "/home/demo/projects/todo-api"}`. A sixth
argument, a JSON file like `{"viewports": [...], "allow": [...]}`, also lays
every tab and dialog out at each viewport and measures it with
`internal/layoutsweep/probe.js`. `tests/demo` passes one; the measurements are
judged there.

## The scrub

`recorder.py`'s `Scrubber` rewrites every string of every answer and frame:

- Paths: the projects become `/home/demo/projects/<name>`, the scratch
  home `/home/demo`, and anything else under `/tmp` or `/root` goes under
  `/home/demo`.
- Hosts: the hub becomes `https://demo.example.com`, the identity provider
  `https://login.demo.example.com`, the wiki and tracker
  `wiki.demo.example.com` and `jira.demo.example.com`, the fake Anthropic
  endpoints `https://api.anthropic.com`, and the machine's name
  `demo.example.com`.
- Credentials: every token and key the recording minted or was given is
  replaced with `[redacted]`, and so is anything shaped like a cloop token
  (`cloop_<kind>_…`).
- E-mail addresses outside `example.com`, `example.org` and `example.net`
  become `someone@demo.example.com`, and MAC addresses are replaced with
  locally administered ones.
- Times: every time within 400 days of the recording moves by the same
  amount, so the recording starts at 09:30 UTC on 16 November 2026, whenever
  it was made. That keeps a re-recording's diff about content.

`tests/demo` then fails on any fixture holding a credential pkg/redact
recognises, a `/root` or `/tmp` path, a host outside the allowed ones, or the
recording machine's name. It also fails when a GET route the dashboard names
has no fixture.

## Traps

- **Run no cloop command from the repository's root.** Any cloop subcommand
  opens and migrates the database of the directory it runs in, and the root
  is the live hub's. The script `cd`s into its scratch directory before
  anything else and runs every cloop command there or in a demo project.
- **Nothing inherited may reach the hub.** Every process runs under
  `env -i` with its own `HOME`, `CLOOP_HOME` and `TMPDIR`, so
  `CLOOP_SECRET_KEY`, `CLOOP_TASK_ID`, `ANTHROPIC_*`, `CLAUDE_*` and
  `GITHUB_TOKEN` stay out. The hub gets a sealing key made for the run.
- **The hub must not see this machine's processes.** Hub health lists every
  `cloop run` it can see, with its directory, and the first recording put this
  machine's own run in the demo. The hub runs under
  `unshare --pid --fork --mount-proc`.
- **`$!` after `cmd &` in a function or a list is a subshell.** Background
  processes are started as `(exec …) &`, so killing `$!` kills them.
- **Only what the script made is cleaned up.** It kills the processes it
  started and every process of its own `cloop` binary, by exact path, and
  removes its scratch directory. It makes no docker objects: the container
  executor runs against a stand-in `docker` that answers the health checks.
  Never prune docker on a shared machine.
- **A token hub listens on every interface.** The hub gets
  `--listen 127.0.0.1`; the fake services listen on loopback, except
  Confluence and Jira on a private address, over TLS.
- **The Anthropic provider's base URL includes `/v1`.** It appends
  `/messages` itself.
- **A reply sent before its request body is read** leaves the body on a
  kept-alive connection, where it is read as the next request (`fakes.py`
  reads every body first).
- **`cloop init` writes an `anthropic:` block** in `config.yaml`. A second one
  is a duplicate key, the project's config no longer loads, and its run fails
  before it starts. `recorder.py setup` edits the block in place.
- **A run that cannot start ends as `initialized`**, not `failed`; the run
  wait treats any status that stays not-running for three polls as the end.
- **On a hub that shares its host with other projects, runs are confined**,
  and the hub's own directory is refused. The overlay opts `todo-api` (the
  hub's directory) out with `executors.host_sandbox.opt_out`, and hub health
  says so.
- **Teams, shares and sessions need single sign-on.** That is why the
  recording uses a fake identity provider. The static token still works for
  seeding; Dana's own session is used where a person is needed (approving a
  gate or a request, the device's access list).
- **The plan assistant keeps its conversation in the page.** A recording has
  none, so the demo's Assistant tab opens on its suggestions.
- **The Budget tab's global daily spend reads $0.** landing-page's runs have
  real token usage and costs, and its Analytics show them, but runs confined
  to their project write the global cost ledger into their sandbox's own
  home (`…/claude-identities/<id>/sandbox-home/.config/cloop/costs.jsonl`),
  which the hub does not read. That is a cloop bug the recording found, and
  the fixtures show it as it is; a recording made after the fix shows the
  spend.
- **Three reads have no fixture on purpose**: a sandbox terminal, the list of
  repositories a GitHub App installation can see (the App is made up), and a
  move's progress (no project is moved). `demoNeedsNoFixture` in
  `tests/demo/fixtures_test.go` names them with the event stream and the
  sign-in pages.

## When a new dashboard read fails tests/demo

Record again, or add a fixture by hand in the format
[website/demo/README.md](../../website/demo/README.md) describes. If the
crawl cannot fetch the new route because it needs a query parameter, add one
to `EXTRA_QUERY` in `recorder.py`; if it takes a new kind of id, teach
`list_for` where to list them.
