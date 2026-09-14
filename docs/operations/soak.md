# Multi-tenant soak

`tests/soak` drives a hub under sustained concurrent load from several tenants
at once and fails on the three things that only break there: cross-tenant
bleed, leaked resources, and unbounded growth.

It exists because the rest of the suite cannot see any of them. The
[flagship circuit](../architecture/executors.md) proves one task completes one
circuit; the security conformance suite machine-checks the guarantees against
the source. Neither runs anything twice at the same moment — and every
isolation defect this project has actually shipped was a concurrency defect.
The cross-tenant live log leak fixed in Task 20189 came from the broadcast path
walking every connected client, which is invisible with one client connected.

## Running it

```bash
CLOOP_SOAK=1 go test -race -timeout 30m ./tests/soak/
```

It is opt-in: it drives the container runtime, writes to machine-global paths,
and takes minutes. Without `CLOOP_SOAK` the soak skips, and only the detector
tests below run.

`-race` is not optional in spirit. A data race in the broadcast path is how a
frame reaches the wrong room in the first place.

### Knobs

Each is a flag with an environment-variable equivalent, so CI can set it
without a shell-quoting argument.

| Flag | Env | Default | What it changes |
| --- | --- | --- | --- |
| `-soak.tasks` | `CLOOP_SOAK_TASKS` | 20 | Total container dispatches |
| `-soak.tenants` | `CLOOP_SOAK_TENANTS` | 3 | Distinct identities competing |
| `-soak.projects-per-tenant` | `CLOOP_SOAK_PROJECTS_PER_TENANT` | 2 | Projects each tenant owns |
| — | `CLOOP_SOAK_IMAGE` | built | Use a prepared sandbox image instead of building one |
| — | `CLOOP_SOAK_BASE_IMAGE` | `alpine:3.20` | Base the built image derives from |
| — | `CLOOP_SOAK_RUNTIME` | auto | Pin `docker` or `podman` |
| — | `CLOOP_SOAK_KEEP` | unset | Leave the soak root in place for post-mortem |

Tenants times projects is the concurrency ceiling, not `-soak.tasks`. The hub
refuses a second simultaneous run on one project — by design, with a 409 — so
the number of projects is the number of containers that can be in flight at
once, and the tasks queue behind them.

Three tenants is the floor the suite enforces. With two, a broadcast bug and a
routing bug look identical.

## What it actually runs

A real hub, in-process, with `allow_host_process: false` — the posture an
enterprise deployment runs in, where the web UI cannot spawn a harness on the
host at all. Real project-scoped API tokens are the tenant boundary. Every task
is a real container dispatched through `POST /api/run`, streamed back through
the real broadcast path, and observed by real WebSocket subscribers: one per
project plus one global-scope connection per tenant.

The one stand-in is the workload. Instead of an agent harness, the sandbox runs
a short script that reads a canary out of its own bind-mounted workspace and
echoes it. That substitution is the point: the suite tests the hub's isolation
of concurrent workloads, not an agent's behaviour, and an unpredictable
workload would make bleed undetectable. Reading the canary from the workspace
rather than the environment is also deliberate — it makes the value a function
of the bind mount the executor set up, so a frame carrying tenant A's canary
proves A's project directory was mounted into the container that produced it.

Each project is also granted a real credential — a kubeconfig, because it is
delivered as bytes on disk rather than as an environment variable, which is the
path the wipe guarantee covers. The workload reports that the credential
arrived and how large it was, and never its contents.

## The three assertions

**Zero cross-tenant bleed.** Every frame delivered to a tenant's subscriber is
scanned for every other tenant's canary and for every project's credential
sentinel. A hit names the recipient, the owner, the task, the frame type and
the payload — a soak that reports "mismatch" teaches nobody anything.

The positive control is part of the assertion, not a diagnostic beside it: each
project-scoped stream must have carried its *own* project's output. A hub that
delivered nothing to anybody would have zero cross-tenant frames and would pass
a leak-only check while being completely broken.

**Zero leaked resources.** After the load settles: no container from this run's
executor survives, no credential staging directory created during the run
remains, no byte of any granted credential is findable on disk, and the
goroutine count has not risen above the post-warm-up baseline by more than a
fixed slack. The slack is fixed rather than proportional to task count on
purpose — a leak that scales with the load is the whole defect class, so a
budget that also scaled would grow to accommodate it.

**Bounded growth.** Control-plane and project database sizes (including the
`-wal` sidecar, without which a commit is invisible to a `stat`), audit row
count, and resident memory are sampled at quarter marks. The check compares the
second half's per-task cost against the first half's rather than against an
absolute ceiling, because that is what distinguishes the defects it stands in
for: the audit amplification fixed in Task 20218 and the unbounded retention
fixed in Task 20229 both look fine at small totals, and what gives them away is
that each additional task costs more than the last.

## The detector tests

`tests/soak` also contains `TestDetector_*`, which run on every `go test ./...`
with no container runtime and no opt-in. They plant each defect — a
cross-tenant frame, a leaked credential in a frame, credential bytes surviving
on disk, a quadratic growth curve — and assert the corresponding detector
reports it, with the right facts in the message.

They exist because the soak's value is entirely in its ability to fail, and a
detector that silently stopped working would otherwise be discovered only by a
soak that quietly passed.

## In CI

The `concurrency-soak` job runs it on every push and pull request, under
`-race`, gating rather than advisory.

The job does not trust the exit code. The suite *skips* when `CLOOP_SOAK` is
unset or no container runtime answers, and a skip exits 0 — so the job requires
each of the three assertions to have passed by name, and requires the log to
show that the configured number of tasks was actually driven. A green status
with any of those missing is reported as an error.

Only the registry pull retries. The soak itself never does: re-running a failed
isolation assertion is how a real regression gets re-run away.

## Notes for operators

**The per-IP WebSocket cap applies fleet-wide behind a proxy.** The hub bounds
concurrent WebSocket connections per source address, defaulting to 8. The soak
raises that bound for itself, because collapsing distinct tenants onto
127.0.0.1 is an artefact of running the hub and its clients in one process.

The same collapse happens for real in a deployment that terminates TLS at a
reverse proxy without setting `behind_proxy`: the hub then sees every client at
the proxy's address, and eight connections — three browser tabs from two users
— exhausts the cap for everyone. The symptom is a dial failing with 429 and a
dashboard that silently falls back to SSE. See
[`hub bootstrap --behind-proxy`](runbook.md).

**Audit appends are best-effort under concurrent load.** With several
dispatches minting leases at once, SQLite can report `database is locked` on an
audit insert; the hub logs one warning, suppresses the rest, and continues. The
trail is a compliance record and the run is not blocked on it, which is the
right trade for availability — but it means an audit row count taken under
heavy concurrency is a lower bound, not an exact one. The soak's growth check
is a ratio between two intervals and is unaffected; an operator reconciling
counts should know it.
