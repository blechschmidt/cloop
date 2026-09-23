# Regenerating the documentation screenshots

```bash
make screenshots          # or: ./scripts/screenshots/capture.sh
```

Writes `docs/screenshots/*.png`. Takes a couple of minutes, most of it the
`go build`.

## Why this exists rather than a folder of images

The images are published. Pointing a camera at a working hub would put whatever
that hub is doing — real projects, real goals, real utilisation numbers — into
the documentation, and "I remembered to hide the private ones first" is a
promise every future regeneration has to keep independently.

So the screenshots are taken of a hub built for the purpose and destroyed
afterwards: three invented projects under `/tmp`, a `CLOOP_HOME` of its own so
the per-user project registry is neither read nor written, a `HOME` of its own
so the Claude Code caps card finds no subscription to report, and a port nothing
else is on. None of that depends on care taken at the time; it is how the thing
is wired.

What the images show is not staged either. The demo hub *runs* `checkout-api`
against the offline `mock` provider and is stopped partway, so the finished
tasks are finished because cloop finished them, the results are the provider's,
and the event history is an event history. The remote executor in
`06-executors.png` is a real agent that really enrolled.

## The pieces

| File | What it is |
| --- | --- |
| `capture.sh` | the entry point: hub up, photograph, hub down |
| `demo-hub.sh` | builds and seeds the throwaway hub (`up` / `down`) |
| `capture.js` | drives headless Chromium over CDP; one entry per shot |
| `plan-*.yaml` | the three demo plans, imported with `cloop plan import` |
| `mock-responses.yaml` | what the `mock` provider answers, per task |

## Requirements

Chromium or Chrome, `node`, and Docker or Podman for the container executor to
come up healthy. `CHROME=/path/to/chrome` overrides the search.

The harness image must be present locally, or the Executors tab photographs a
preflight failure instead of an online executor:

```bash
docker pull ghcr.io/blechschmidt/cloop-harness:latest
# or point at one you already have
CLOOP_DEMO_IMAGE=cloop-harness:dev make screenshots
```

Not wired into CI on purpose: screenshots that regenerate on every push are a
binary diff on every push.

## Adding or changing a shot

Add an entry to `SHOTS` in `capture.js`. A shot names the file, the JS that puts
the page into the state worth photographing, a predicate that has to be true
before the shutter, and what to frame.

Prefer `clipTo` over `maxHeight` when there is a natural boundary: `clipTo` cuts
where a named element begins, so the crop still lands between the same two
panels after somebody adds a field to the one above it.

Then update the prose. `docs/getting-started/walkthrough.md` and
`web-ui.md` describe these images in their alt text, and alt text that no longer
matches the picture is worse than none — it is the version screen readers get.
