# Front-end telemetry

The hub collects a diagnostic trail from the browser dashboard and from the
display-glasses page, so that a front-end defect can be investigated from the
outside.

It is **off by default**. Nothing is collected, and nothing is sent, until an
operator switches it on — see [turning it on](#turning-it-on).

## Why it exists

The hub's front ends run on machines it cannot inspect. For the dashboard that
is inconvenient. For the Meta Ray-Ban Display page it is total: those glasses
have no developer tools, no console, no network inspector, and the wearer's
only reporting channel is a sentence of prose.

Three tasks in this project's own history were spent reproducing such a
sentence by simulation — "swiping right selects the first element once and then
does not move again" was diagnosed by building a model of the device and
guessing until the guess matched the prose.

So the unit of collection is not the exception. Almost none of those failures
threw. It is the **breadcrumb**: an ordered trail of what the page did — the
gesture it received, the view it opened, the request it issued and the status
that came back — with errors as one kind of entry among several.

A trail answers "the cursor never moved past the first row" directly, because
the gesture events are in it and the focus changes are not:

```
08:46:47.101    3 gesture    next   {"key":"ArrowRight","ring":28,"at":1}
08:46:47.104    4 gesture    next → 2   {"after":2,"ring":28}
```

`at` is where the cursor was when the gesture arrived; `after` is where it
ended up. Two consecutive entries with the same value are the reported bug.

## What is recorded

| Kind | Meaning |
| --- | --- |
| `error` | an uncaught exception, with its stack |
| `rejection` | an unhandled promise rejection |
| `gesture` | an input the page received — a key, swipe, pinch or click |
| `input` | an input the page received and did **not** act on |
| `view` | a tab or screen the page opened |
| `fetch` | a request the page issued, with status and duration |
| `lifecycle` | page load, visibility change, a link reaching its terminal state |
| `note` | anything else, and where an unrecognised kind lands |

### Reading a glasses trail

Three fields on a `gesture` carry most of the diagnostic weight, and each was
added because an investigation stalled without it.

`ch` is the channel the input arrived on — `key`, `touch` or `wheel`. The first
real Ray-Ban Display trail recorded a pinch as `Enter` and, for a sideways
swipe, nothing at all: the page listened only for keydown, so a gesture that
came in as touch left no trace and "the swipe did nothing" could not be
distinguished from "the swipe never happened". Every gesture now names its
channel, so that question is a query.

`ae` is `document.activeElement` at the moment of the gesture. The page does not
*trust* focus — it owns the cursor in a variable, because the device's focus
model cannot be relied on — but the device does aim its key events at whatever
is focused. An `ae` of `body` while controls are on screen is a page with
nowhere to receive the next gesture.

A row of kind `input` is the complement: the page saw something and could not
name it. Taps and vertical drags are excluded, because those are meant to end
up unhandled; what is left is a gesture arriving on a channel nothing handles
yet — which is exactly the shape of the failure above, and the first thing to
look for when a wearer reports that a gesture does nothing.

Silence is also evidence, but only alongside `lifecycle`. A trail that stops
has two readings — the wearer looked away, or the page stopped receiving input
— and they call for opposite fixes. A `lifecycle` row of `hidden` means the
first; missing gestures with no such row means the second.

Each event carries the session (one page load), a monotonic sequence number,
the page's own clock, the view it happened in, and a small free-form detail
blob. The hub adds what the page does not get to assert: the arrival time, the
client address, the user agent, the authenticated identity, and the hub build
that served the page.

**Sequence numbers, not timestamps, are the ordering.** Events are batched,
batches race in flight, and a wearable's absolute clock is routinely wrong. A
gap in `seq` means a batch was lost, which is itself a finding.

## Reading a trail

From a terminal, which is usually where an investigation starts:

```bash
cloop hub telemetry sessions                   # recent page loads, newest first
cloop hub telemetry sessions --source glasses  # just the wearable
cloop hub telemetry show <session>             # one trail, in order, forwards
cloop hub telemetry show <session> -v          # with urls, stacks and detail
cloop hub telemetry list --kind error          # recent errors across all sessions
cloop hub telemetry list --grep /api/tasks     # anything touching an endpoint
```

Start with `sessions`. An investigation arrives as "somebody reported a problem
around ten past four" and has to become a session id before anything else is
useful.

Run these from the hub's own directory, or pass `--workdir`. They refuse to
create a database they cannot find rather than reporting an empty one — "no
telemetry recorded" from the wrong directory reads as "the instrument is
broken".

In the dashboard, the same data is under the **Telemetry** tab, gated on
`audit.read`. Clicking a session row filters the events below it.

Over HTTP:

```
GET /api/telemetry?source=&kind=&session=&q=&since=&limit=&offset=
GET /api/telemetry/sessions?source=&limit=
```

Both require **`audit.read`** and are global in scope — the same permission and
the same reasoning as the audit trail. A trail carries URLs, view names, user
agents and error text from other people's sessions, which is the same class of
cross-tenant operational record.

## What is not stored

Credentials are stripped at ingest, before anything reaches the database.

The load-bearing case is the display-glasses link, which carries its bearer
token **in the page URL** and is valid for thirty days. `location.href` is the
natural value for an event's URL field, so without scrubbing the first trail a
wearer produced would copy a live credential into a table that a different
permission can read.

Scrubbing is deliberately over-eager. It redacts the value of any sensitive
query parameter (`token`, `code`, `id_token`, `secret`, `key`, `password`,
`authorization`, and others), anything following `Bearer `, and any run
beginning with a cloop credential prefix — wherever they appear, including
inside a message or a stack frame, not only in a well-formed URL.

```
/glasses?token=cloop_glasses_7f3a_2b91  →  /glasses?token=[redacted]
```

The path survives, because the path is the part worth reading.

A redacted field you can ask a colleague about is recoverable. A leaked
credential in a table is not.

## Limits

Telemetry is bounded at every layer, because ingest is the one route that
accepts a body without requiring a permission.

| Bound | Value | Where |
| --- | --- | --- |
| Request body | 2 MiB | `telemetryMaxBodyBytes` — deliberately below the 10 MiB default |
| Events per batch | 64 | `telemetry.MaxBatchEvents` |
| Message / stack / URL / detail | 2 / 8 / 1 / 4 KiB | `pkg/telemetry` |
| Events per page load | 500, of which 150 routine | the browser reporter |
| Rows in the table | 50,000 | `statedb.TelemetryMaxRows` |

The row ceiling is enforced **on the write path**, not by the hourly retention
janitor: a bound that only holds once an hour is not a bound against an
endpoint that takes unauthenticated-by-permission writes. The table trims its
oldest rows once it drifts past the ceiling, so it cannot grow without limit
and pruning is never required for disk.

To delete a trail sooner than it would age out:

```bash
cloop hub telemetry prune --before 7d
```

Unlike the audit trail, telemetry is not hash-chained and nothing verifies its
continuity, so deletion needs no seal and leaves no gap to explain.

## Authentication

Ingest declares **no permission**, for the same reason `POST /api/client-error`
does not: an instrument that records only while the page is healthy records
nothing about the failures worth investigating, and a user whose role grants
nothing still has a broken page to report.

Public here means *no permission*, not *no credential*. Both ingest routes
still sit behind the authentication middleware, so they reach exactly the
people already entitled to load a page and never an anonymous scanner.

There are two ingest routes rather than one, and a matching pair that answer
"may I send at all":

```
POST /api/telemetry                   the dashboard
POST /api/glasses/telemetry           the wearable
GET  /api/telemetry/config            may I send?
GET  /api/glasses/telemetry/config    may I send?
```

Each front end asks the second before it uses the first, once per page load, and
holds its events until the answer arrives. That is what makes "off" mean *not
submitted* rather than *submitted and refused*: a page that posted first and
read the `404` would already have sent the trail — over the network and past
whatever sits in between — on exactly the hub that wanted none of it.

The probe discloses one boolean about the asking page and fails closed: an
answer that is missing, refused or unparseable leaves the trail off for that
page load. The hub still refuses the ingest independently, so a hand-written
client that skips the question gains nothing.

A display-glasses token is pinned to the `/glasses` and `/api/glasses/`
prefixes, and that pin is load-bearing — it is what stops a credential living
in a URL from reaching the routes that return agent transcripts. Widening it so
the glasses could post to `/api/telemetry` would trade the whole of that
containment for one endpoint, so the wearable gets its own path inside the
prefix it already has.

One consequence is worth knowing: a glasses link that has already been revoked
cannot deliver its final events, because its credential stops working first.
Everything up to that point has been flushed, and the terminal state is what
the page reports to the wearer in plain words anyway.

Both routes answer `204` for everything they accept **and** everything they
drop. A page must not learn from a status code whether its events were kept —
a client that retried on failure would amplify exactly the runaway-loop case
the caps exist to contain.

## Turning it on

In the dashboard: **Settings → Telemetry**, tick the box, Save. It applies to
the next page load — there is nothing to restart — and records a
`telemetry.config.updated` audit row naming who turned it on.

Each front end can be enabled separately. `glasses` alone is a sensible
deployment posture: the display-glasses page is the one that cannot be debugged
any other way, and the dashboard is the one that produces most of the volume and
holds most of the privacy cost.

The same thing in config, if you would rather deploy it than click it:

```yaml
ui:
  telemetry:
    enabled: true
    sources: [glasses]   # optional; omit for every front end
```

The panel needs `user.manage`, which is admin-only — one step stronger than the
`config.write` the rest of Settings uses. Reading a trail back is `audit.read`,
also admin-only, and switching the recording on is the same decision taken one
step earlier.

Collection is a setting of the hub, not of a project. A hub that has a
[per-instance overlay](../reference/configuration.md#two-dashboards-in-one-directory) —
`.cloop/config.ui-<port>.yaml`, for two dashboards sharing one working
directory — reads it through that overlay and the panel saves it there, so each
of the two decides for itself, and an older binary rewriting the shared
`config.yaml` (which drops keys it does not know) cannot switch it off.

### Where the events go

To this hub, and only to this hub. There is deliberately no setting that points
the front ends at a third-party collector, for two reasons that are worth
stating rather than leaving to be rediscovered:

- The dashboard is served under `Content-Security-Policy: connect-src 'self'`.
  A cross-origin POST is refused by the browser, so such a setting would need
  the hub to weaken its own CSP for every page it serves.
- Scrubbing happens at ingest, in the hub. The display-glasses page carries its
  bearer token in the page URL, so a trail sent anywhere else would take a live
  credential with it — which is precisely the leak `Scrub` exists to prevent.

A fleet that wants one collector should relay hub-side, after scrubbing, rather
than from the browser. Nothing does that today.

## Why off by default

This shipped on by default, and the argument was a real one: an instrument that
has to be switched on in advance is never on when the failure it was built for
happens.

It weighs the wrong interest. A trail carries the URLs somebody visited, the
views they opened, their user agent and their address. Collecting that is a
decision about other people's data, and on a hosted hub the operator and the
recorded person are not the same person. A deployment that has never heard of
this setting has not made that decision — and defaulting to collection makes it
silently, on behalf of an operator who would in many jurisdictions have to
disclose it.

So the instrument is opt-in, and the cost of that is paid in the one place it
shows: the first report of a glasses defect on a fresh hub arrives with no trail
behind it. Switch collection on, ask the wearer to reproduce it once, and the
second report has one.

## Turning it off again

Untick the box, or:

```yaml
ui:
  telemetry:
    enabled: false
```

Both ingest routes then answer `404` rather than silently discarding, so the
setting is verifiable, and the front ends stop posting at all. Reading
previously-collected events still works — **switching collection off deletes
nothing**. Use `cloop hub telemetry prune` to remove what was already gathered;
the panel shows how much that is.

## Where errors also go

Events of kind `error` and `rejection` are additionally written to the
structured logger as `client_error` entries, so an operator who reads the
journal and never opens the panel still sees browser errors. This preserves the
behaviour that predated the trail.
