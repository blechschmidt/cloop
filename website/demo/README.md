# The dashboard demo

The documentation site hosts a copy of the cloop dashboard at `/demo/`
(<https://blechschmidt.github.io/cloop/demo/>). It is the real dashboard,
running in the reader's browser against canned data, so someone can look
around before installing anything.

Nobody wrote this page by hand. `scripts/build-demo.py` copies the
dashboard's own files out of `pkg/ui/assets` when the site is built, in the
order `pkg/ui/static.go` assembles them for the hub, and adds the three files
in this directory:

| File | What it does |
| --- | --- |
| `shim.js` | Loaded before any of the dashboard's scripts. It stands in for the hub (see below). |
| `banner.html`, `demo.css` | The bar across the top that says this is a demo with canned data and links to the install guide. `demo.css` also moves the dashboard's sticky header down by the bar's height. |
| `fixtures/` | The canned answers. |

The build also gives the page the Content-Security-Policy the hub sends with
the dashboard, in a `<meta>` element, because GitHub Pages sends none. With it
the browser itself refuses any request to another site and any script that is
not one of the demo's files.

Nothing here is compiled into cloop: the hub never serves these files, and
`pkg/ui/assets` is only read.

## Building it

```bash
make docs-site                              # the whole site, the demo included
make docs-demo                              # only the demo, into dist/docs-site/demo
python3 -m http.server -d dist/docs-site 8000
```

Then open <http://127.0.0.1:8000/demo/>. `make docs-serve` does not show the
demo, because mkdocs does not build it.

The Documentation site workflow runs `make docs-site` and publishes the result,
so the demo is rebuilt whenever the dashboard (`pkg/ui/assets`,
`pkg/ui/static.go`), this directory or the build script changes.

## What the shim does

The dashboard expects a hub at the root of its own origin. On github.io there
is none, so `shim.js` replaces `fetch`, `XMLHttpRequest`, `WebSocket`,
`EventSource` and `navigator.sendBeacon` before the dashboard loads:

- A read of a hub route (`/api/…`, `/auth/…`, or any other absolute path
  outside the demo's directory) is answered from the fixtures. A read with no
  fixture gets an empty JSON object, `{}`, with status 200, so the panel
  draws as empty instead of failing.
- Every `POST`, `PUT`, `PATCH` and `DELETE` is refused in the page with status
  405 and the message "This is a read-only demo. Install cloop to try this.",
  which the dashboard's toast shows. Two background posts are refused without
  the toast: the telemetry trail and the Requirements tab's spec read.
- A socket opens, sends the frames recorded for its URL, and then stays quiet.
  What the page sends on it is dropped.
- Nothing calls out. A request to another origin is answered in the page like
  a hub route. The hub's answer to whether to collect telemetry is always no,
  dictation is always unavailable, and the microphone is refused. Links,
  windows and frames that would open a hub page (`/auth/login`, `/glasses`)
  show the toast instead, and so does sign-out. Claude sign-in starts with a
  `POST`, so it is refused before it can open claude.ai.

`window.cloopDemo.requests()` lists every request the page has made, whose it
was and how it was answered. To find what a panel asks for that no fixture
answers yet, open it and run this in the browser console:

```js
cloopDemo.requests().filter(r => r.answer === 'empty')
```

## Fixtures

Each `*.json` file under `fixtures/` holds one fixture or a list of them.
Subdirectories are only for keeping them apart; the build reads them all.

```json
{
  "request": "GET /api/executors?project_idx=0",
  "note": "Optional: why this fixture exists.",
  "body": {"executors": []}
}
```

| Field | Meaning |
| --- | --- |
| `request` | The method and the path, with the query. `GET` answers `GET` and `HEAD`; `WS` answers a socket. |
| `body` | The JSON the hub answers with. |
| `text`, `type` | Instead of `body`, a body that is not JSON, and its media type. |
| `status` | The HTTP status, 200 if left out. 401 and 403 are refused, because the dashboard answers them by sending the reader to sign in. |
| `frames` | For `WS`: the messages the socket sends after it opens, in order. The hub's own are `{"type": …, "data": …}`. |
| `note` | Ignored. |

A request is matched by its method, its path and its query parameters, in
any order. `token`, `_`, `t`, `ts`, `nonce`, `n` and `cb` are ignored, because
they never change what a request asks for. A query of `*`, or one ending in
`&*`, matches any further parameters: `GET /api/me?*` answers `/api/me` with
or without `?project_idx=0`. An exact match wins over a `*` one.

A fixture can use another fixture's body instead of repeating it:
`{"$fixture": "GET /api/state?project_idx=0"}` is replaced by that fixture's
body, and `"at"` picks a part of it with a JSON pointer, as
`{"$fixture": "GET /api/state?project_idx=0", "at": "/plan/tasks/0"}` does
for the first task. The project's socket uses this to send the state document
that `GET /api/state` answers with.

The build checks every fixture and stops on an unknown field, a request line it
cannot read, two fixtures for the same request, or a reference to nothing.

## Where the fixtures come from

They are recorded, not written: `scripts/demo/record-fixtures.sh` runs three
made-up projects (`todo-api`, `landing-page`, `csv-report`) through a
throwaway hub with single sign-on, fills its admin surfaces through its own
API, walks the dashboard as an administrator, and writes what the hub
answered, scrubbed of paths, hosts, credentials and real times.
[scripts/demo/README.md](../../scripts/demo/README.md) describes what it
records and how, and how to record again.

`tests/demo` fails when a GET route the dashboard's scripts name has no
fixture, or a fixture holds a credential, a `/root` or `/tmp` path, or a host
that is not made up or public. A dashboard change that adds a read therefore
needs a new recording, or a fixture added by hand in the format above.

## Checking it in a browser

`tests/demo` also opens the demo in headless Chrome, the way a reader does
(`browser_test.go`). It builds the demo with `scripts/build-demo.py`, serves
it from a local server under `/cloop/`, as GitHub Pages does, and runs
`scripts/demo/walk.js check` against it. The walk:

- opens every tab of the hub and of each of the three projects, each task's
  details, and the main admin dialogs: an executor's details and firewall, the
  form that enrolls a machine, a new secret, a grant, a knowledge source, the
  approvals inbox and an audit row's details;
- lays each of them out at a phone (360 px), a tablet (768 px) and a desktop
  (1280 px) width and measures them with the dashboard's own layout probe, so
  the demo and the dashboard follow the same rules for what counts as
  overflowing (`internal/layoutsweep`);
- presses **Add task**, **Start run** and **Delete** on the last project's
  Tasks tab.

The test fails when the page throws or logs an error, when a request goes to
any server other than the local one (in the browser or in the shim) or asks
the local server for anything outside the demo's directory, when anything
overflows, and when a write is not refused with the read-only notice or
changes what the Tasks tab shows.

```bash
make test-demo     # the fixture checks and the browser sweep

# Against a site you have already built with make docs-site:
CLOOP_DEMO_SITE=dist/docs-site go test -run TestTheDemoInABrowser -v ./tests/demo/

# Keep what the walk recorded (every tab, dialog, write and measurement):
CLOOP_DEMO_REPORT=/tmp/report.json go test -run TestTheDemoInABrowser ./tests/demo/
```

The sweep needs Chrome or Chromium, node 22 or later and python3, and skips
without them, like the dashboard's other browser tests. CI runs `tests/demo`
in the **Dashboard demo in a browser** job, which fails if the sweep skipped.
A dashboard change that breaks the demo therefore fails CI, even when the
dashboard itself still passes.
