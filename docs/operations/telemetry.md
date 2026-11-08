# Front-end telemetry

The hub can collect a diagnostic trail from the browser dashboard and from the
display-glasses page, so that you can investigate a front-end defect from the
outside.

It is **off by default**. Nothing is collected or sent until an operator
switches it on (see [turning it on](#turning-it-on)).

## Why it exists

The hub's front ends run on machines it cannot inspect. For the dashboard that
is inconvenient. For the Meta Ray-Ban Display page there is no other way in:
the glasses have no developer tools, no console and no network inspector, and
the wearer can only describe the problem in words.

Without a trail, a report such as "swiping right selects the first element once
and then does not move again" has to be diagnosed by building a model of the
device and guessing until the guess matches the description.

Almost none of those failures throw an exception, so telemetry records
**breadcrumbs**: an ordered trail of what the page did, such as the gesture it
received, the view it opened, the request it sent and the status that came
back. Errors are one kind of entry among several.

A trail answers "the cursor never moved past the first row" directly, because
the gesture events are in it and the focus changes are not:

```
08:46:47.101    3 gesture    next   {"key":"ArrowRight","ring":28,"at":1}
08:46:47.104    4 gesture    next → 2   {"after":2,"ring":28}
```

`at` is where the cursor was when the gesture arrived, and `after` is where it
ended up. Two consecutive entries with the same value are the reported bug.

## What is recorded

| Kind | Meaning |
| --- | --- |
| `error` | an uncaught exception, with its stack |
| `rejection` | an unhandled promise rejection |
| `gesture` | an input the page received: a key, swipe, pinch or click |
| `input` | an input the page received and did **not** act on |
| `view` | a tab or screen the page opened |
| `fetch` | a request the page sent, with status and duration |
| `lifecycle` | page load, visibility change, a link reaching its terminal state |
| `note` | anything else, and where an unrecognised kind lands |
| `csp` | something the hub's Content-Security-Policy blocked, taken from the report the browser sent to `POST /api/csp-report` (not from the page's script): its directive, the blocked URL or `inline`, and the source line. It is recorded under the front end whose document it was, so that front end's collection switch applies, and under the signed-in user whose browser sent it, or nobody. Hub-wide budgets apply: 60 a minute for signed-in browsers' reports and one a minute for anonymous ones, so a flood of forged reports can't push everything else out of the table. [The metric](metrics.md#what-the-pages-policy-blocked) counts every report |

### Reading a glasses trail

Besides `at` and `after`, two fields on a `gesture` do most of the diagnostic
work.

`ch` is the channel the input arrived on: `key`, `touch` or `wheel`. It tells
"the swipe did nothing" apart from "the swipe never arrived". The first real
Ray-Ban Display trail recorded a pinch as `Enter` and a sideways swipe not at
all, because the page listened only for keydown and the swipe came in as touch.
Every gesture now records its channel, so you can query for this.

`ae` is `document.activeElement` at the moment of the gesture. The page keeps
its own cursor in a variable, because the device's focus model is unreliable,
but the device still sends key events to whatever has focus. An `ae` of `body`
while controls are on screen means the page has nowhere to receive the next
gesture.

A row of kind `input` is the opposite case: the page saw an input and could not
identify it. Taps and vertical drags are left out, because they are meant to go
unhandled. What remains is a gesture arriving on a channel that nothing handles
yet, which is the failure described above. Look for these rows first when a
wearer reports that a gesture does nothing.

A trail that stops can mean two things, and they need opposite fixes: the
wearer looked away, or the page stopped receiving input. Check `lifecycle`. A
`lifecycle` row of `hidden` means the first. Missing gestures with no such row
mean the second.

Each event carries the session (one page load), a monotonic sequence number,
the page's own clock, the view it happened in, and a small free-form detail
blob. The hub adds the fields the page can't vouch for: the arrival time, the
client address, the user agent, the authenticated identity, and the hub build
that served the page.

Order events by sequence number, not by timestamp. Events are sent in batches,
batches can overtake each other, and a wearable's clock is often wrong. A gap
in `seq` means a batch was lost, which is useful to know in itself.

## Reading a trail

From a terminal:

```bash
cloop hub telemetry sessions                   # recent page loads, newest first
cloop hub telemetry sessions --source glasses  # just the wearable
cloop hub telemetry show <session>             # one trail, in order, forwards
cloop hub telemetry show <session> -v          # with urls, stacks and detail
cloop hub telemetry list --kind error          # recent errors across all sessions
cloop hub telemetry list --grep /api/tasks     # anything touching an endpoint
```

Start with `sessions`. A report like "somebody had a problem around ten past
four" has to be matched to a session id before anything else helps.

Run these from the hub's own directory, or pass `--workdir`. If they can't find
the database, they exit with an error instead of creating an empty one,
because "no telemetry recorded" from the wrong directory would look like
broken telemetry.

In the dashboard, the same data is in the **Telemetry** tab, which needs
`audit.read`. Click a session row to filter the events below it.

Over HTTP:

```
GET /api/telemetry?source=&kind=&session=&q=&since=&limit=&offset=
GET /api/telemetry/sessions?source=&limit=
```

Both need `audit.read` and are global in scope, like the audit trail: a trail
carries URLs, view names, user agents and error text from other people's
sessions, the same kind of cross-tenant operational record.

## What is not stored

Credentials are stripped at ingest, before anything reaches the database.

The most important case is the display-glasses link, which carries its bearer
token in the page URL and is valid for thirty days. An event's URL field
naturally holds `location.href`, so without scrubbing, the first trail a wearer
produced would copy a live credential into a table that a different permission
can read.

Scrubbing runs in two passes over the message, the stack, the URL and the
detail, and finds credentials inside a message or a stack frame as well as in a
well-formed URL.

The first pass uses the credential registry that `cloop audit` and both audit
trails also use: cloop's own tokens, GitHub tokens in both forms, Anthropic and
OpenAI keys, JWTs, private keys, Authorization values, passwords in URLs, and
every other shape on the [credential patterns](../reference/credential-patterns.md)
page.

The second pass is telemetry's own, and it removes more than strictly needed:
it replaces the value of any sensitive query parameter (`token`, `code`,
`id_token`, `secret`, `key`, `password`, `authorization`, and others) whether or
not it looks like a credential. It runs second because it ends a value at a
space. Run first over `authorization=Bearer <token>`, it would replace only
`Bearer`, the word the registry needs to find the token behind it.

```
/glasses?token=cloop_pat_0f3a…_9c1d…            →  /glasses?token=[redacted]
fetch failed: 401 for Bearer eyJhbGciOiJSUzI1…  →  fetch failed: 401 for Bearer [redacted]
```

The path is kept, and so is whatever identified the credential, because those
are the parts you need to read.

## Limits

Telemetry is limited at every layer, because ingest is the one route that
accepts a body without requiring a permission.

| Bound | Value | Where |
| --- | --- | --- |
| Request body | 2 MiB | `telemetryMaxBodyBytes`, below the 10 MiB default |
| Events per batch | 64 | `telemetry.MaxBatchEvents` |
| Message / stack / URL / detail | 2 / 8 / 1 / 4 KiB | `pkg/telemetry` |
| Events per page load | 500, of which 150 routine | the browser reporter |
| Rows in the table | 50,000 | `statedb.TelemetryMaxRows` |

The row limit is enforced on the write path, not by the hourly retention
janitor, because a limit checked once an hour doesn't hold against an endpoint
that accepts writes without a permission. Once the table goes past the limit,
it trims its oldest rows, so it can't grow without bound and you never have to
prune it to save disk.

To delete a trail sooner than it would age out:

```bash
cloop hub telemetry prune --before 7d
```

Unlike the audit trail, telemetry is not hash-chained and nothing checks its
continuity, so deleting needs no seal and leaves no gap to explain.

## Authentication

The ingest routes require no permission, for the same reason
`POST /api/client-error` doesn't: a page that can only report while it is
healthy reports nothing about the failures you need to investigate, and a user
whose role grants nothing can still have a broken page to report.

No permission does not mean no credential. Both ingest routes sit behind the
authentication middleware, so only people who may already load a page can
reach them, and an anonymous scanner can't.

There are two ingest routes, and a matching pair that answer "may I send at
all":

```
POST /api/telemetry                   the dashboard
POST /api/glasses/telemetry           the wearable
GET  /api/telemetry/config            may I send?
GET  /api/glasses/telemetry/config    may I send?
```

Each front end asks its config route once per page load, before it uses the
ingest route, and holds its events until the answer arrives. So when telemetry
is off, nothing is sent at all. A page that posted first and then read the
`404` would already have sent the trail over the network, through whatever
sits in between, to the hub that wanted none of it.

The config route reveals one boolean about the asking page and fails closed: if
the answer is missing, refused or unparseable, the trail stays off for that page
load. The hub also refuses ingest on its own, so a hand-written client that
skips the question gains nothing.

A display-glasses token works only under the `/glasses` and `/api/glasses/`
prefixes, which stops a credential that lives in a URL from reaching the routes
that return agent transcripts. Widening that so the glasses could post to
`/api/telemetry` would give up all of this protection for one endpoint, so the
wearable has its own route inside the prefix it already has.

As a result, a glasses link that has already been revoked can't deliver its
final events, because its credential stops working first. Everything up to
that point has been sent, and the page tells the wearer about the final state
in plain words anyway.

Both routes answer `204` for everything they accept **and** everything they
drop, so a page can't learn from the status code whether its events were kept.
A client that retried on failure would make the runaway-loop case, which the
limits exist to contain, worse.

## Turning it on

In the dashboard, open **Settings → Telemetry**, tick the box and click
**Save**. The change applies from the next page load, with nothing to restart,
and records a `telemetry.config.updated` audit row naming who turned it on.

You can enable each front end separately. Enabling `glasses` alone is a
sensible setup: the display-glasses page can't be debugged any other way, while
the dashboard produces most of the volume and carries most of the privacy cost.

To set the same thing in the configuration file:

```yaml
ui:
  telemetry:
    enabled: true
    sources: [glasses]   # optional; omit for every front end
```

The panel needs `user.manage`, which only admins have. That is one step
stronger than the `config.write` the rest of Settings uses. Reading a trail
back needs `audit.read`, also admin-only, and switching recording on is the
same decision made one step earlier.

Collection is a hub setting, not a project setting. A hub with a
[per-instance overlay](../reference/configuration.md#two-dashboards-in-one-directory)
(`.cloop/config.ui-<port>.yaml`, for two dashboards sharing one working
directory) reads the setting through that overlay, and the panel saves it
there. Each of the two hubs decides for itself, and an older binary that
rewrites the shared `config.yaml` (dropping keys it doesn't know) can't switch
it off.

### Where the events go

Only to this hub. There is no setting that points the front ends at a
third-party collector, for two reasons:

- The dashboard is served under `Content-Security-Policy: connect-src 'self'`.
  The browser refuses a cross-origin POST, so such a setting would need the hub
  to weaken its own CSP for every page it serves.
- Scrubbing happens at ingest, in the hub. The display-glasses page carries its
  bearer token in the page URL, so a trail sent anywhere else would take a live
  credential with it, which is the leak `Scrub` exists to prevent.

A fleet that wants one collector should relay from the hub, after scrubbing,
not from the browser. Nothing does that today.

## Why off by default

Telemetry first shipped switched on, because telemetry that has to be switched
on in advance is off when the failure it was built for happens.

That argument puts the wrong interest first. A trail carries the URLs somebody
visited, the views they opened, their user agent and their address. Collecting
that is a decision about other people's data, and on a hosted hub the operator
and the recorded person are different people. A deployment that has never
heard of this setting has not made that decision, and collecting by default
would make it for them without telling them, although in many jurisdictions the
operator would have to disclose it.

The cost of opt-in is that the first report of a glasses defect on a fresh hub
arrives without a trail. Switch collection on, ask the wearer to reproduce the
problem once, and the second report will have one.

## Turning it off again

Untick the box, or:

```yaml
ui:
  telemetry:
    enabled: false
```

Both ingest routes then answer `404` instead of discarding events without an
error, so you can check that the setting took effect, and the front ends stop
posting altogether. You can still read events collected earlier: switching
collection off deletes nothing. Use `cloop hub telemetry prune` to remove them;
the panel shows how much there is.

## Where errors also go

Events of kind `error` and `rejection` are also written to the structured
logger as `client_error` entries, so an operator who reads the journal and
never opens the panel still sees browser errors. This keeps the behaviour from
before the trail existed.
