# Multi-tenant soak

`tests/soak` runs a hub under sustained, concurrent load from several tenants
at once. It fails on three kinds of defect that only show up under that load:
cross-tenant bleed (one tenant's output reaching another), leaked resources,
and unbounded growth.

The rest of the suite can't catch these. The
[flagship circuit](../architecture/executors.md) runs one task through one
circuit, and the security conformance suite checks the guarantees against the
source. Neither runs two things at once, yet every isolation defect this
project has shipped was a concurrency defect. One cross-tenant live log leak
came from the broadcast path going through every connected client, which you
can't see with only one client connected.

## Running it

```bash
CLOOP_SOAK=1 go test -race -timeout 30m ./tests/soak/
```

It is opt-in because it drives the container runtime, writes to
machine-global paths and takes minutes. Without `CLOOP_SOAK` it is skipped, and
only the detector tests below run.

Always run it with `-race`. A data race in the broadcast path is how a frame
reaches the wrong room in the first place.

### Knobs

Each setting is a flag with an equivalent environment variable, so CI can set
it without quoting shell arguments.

| Flag | Env | Default | What it changes |
| --- | --- | --- | --- |
| `-soak.tasks` | `CLOOP_SOAK_TASKS` | 20 | Total container dispatches |
| `-soak.tenants` | `CLOOP_SOAK_TENANTS` | 3 | Distinct identities competing |
| `-soak.projects-per-tenant` | `CLOOP_SOAK_PROJECTS_PER_TENANT` | 2 | Projects each tenant owns |
| | `CLOOP_SOAK_IMAGE` | built | Use a prepared sandbox image instead of building one |
| | `CLOOP_SOAK_BASE_IMAGE` | `alpine:3.20` | Base image for the built image |
| | `CLOOP_SOAK_RUNTIME` | auto | Pin `docker` or `podman` |
| | `CLOOP_SOAK_KEEP` | unset | Leave the soak root in place for a post-mortem |

The concurrency limit is tenants times projects per tenant, not `-soak.tasks`.
The hub refuses a second simultaneous run on the same project with a 409, so
the number of projects is the number of containers that can run at once, and
the remaining tasks queue behind them.

The suite runs three tenants by default, because three is the smallest number
that tells "A leaked to B" apart from "everyone sees everything": with two, a
broadcast bug and a routing bug look the same. It refuses to run with fewer
than two.

## What it actually runs

A real hub runs in the test process with `allow_host_process: false`, as in
an enterprise deployment, where the web UI can't start a harness on the host.
Real project-scoped API tokens separate the tenants. Every task is a real
container started through `POST /api/run`, and its output comes back through
the real broadcast path to real WebSocket subscribers: one per project, plus
one global-scope connection per tenant.

Only the workload is a stand-in. Instead of an agent harness, the sandbox runs
a short script that reads a canary from its bind-mounted workspace and prints
it. The suite tests how the hub isolates concurrent workloads, not how an agent
behaves, and unpredictable output would make bleed impossible to detect. The
canary is read from the workspace, not the environment, so a frame carrying
tenant A's canary proves that A's project directory was mounted into the
container that produced it.

Each project is also granted a real credential: a kubeconfig, because it is
delivered as a file on disk, which is what the wipe guarantee covers. The
workload reports that the credential arrived and its size, never its
contents.

## The three assertions

**Zero cross-tenant bleed.** Every frame delivered to a tenant's subscriber is
searched for every other tenant's canary and for every project's credential
sentinel. A match is reported with the recipient, the owner, the task, the
frame type and the payload, so the failure says what leaked and where.

The assertion also includes a positive control: each project-scoped stream must
have carried its *own* project's output. Without it, a hub that delivered
nothing to anybody would have zero cross-tenant frames and would pass.

**Zero leaked resources.** Once the load has settled, the soak checks that no
container from this run's executor is left, no credential staging directory
created during the run remains, no byte of any granted credential is on disk,
and the goroutine count is at most a fixed slack above the baseline taken after
warm-up. The slack doesn't grow with the number of tasks, because the leaks it
looks for do, and an allowance that grew with them would hide them.

**Bounded growth.** The soak samples the control-plane and project database
sizes (including the `-wal` file, without which a `stat` doesn't see a commit),
the audit row count and resident memory at each quarter of the run. It compares
the second half's cost per task with the first half's, not with an absolute
ceiling, because defects such as audit amplification and unbounded retention
(this project has had both) look fine at small totals. What gives them away is
that each task costs more than the last.

## The detector tests

`tests/soak` also contains `TestDetector_*`. These run on every `go test ./...`
and need no container runtime and no opt-in. Each one plants a defect (a
cross-tenant frame, a leaked credential in a frame, credential bytes left on
disk, a quadratic growth curve) and checks that the matching detector reports
it, with the right details in the message.

The soak is only useful if it can fail. Without these tests, a detector that
stopped working would only show up as a soak that kept passing.

## In CI

The `concurrency-soak` job runs the soak with `-race` on every push and pull
request, and a failure fails the build.

The job doesn't rely on the exit code, because the suite skips when
`CLOOP_SOAK` is unset or no container runtime responds, and a skip exits 0. It
also checks the log: each of the three assertions must have passed by name, and
the configured number of tasks must have run. If either is missing, the job
reports an error.

Only the image pull from the registry is retried. The soak itself is never
retried, because retrying a failed isolation assertion until it passes would
hide a real regression.

## Notes for operators

**The per-IP WebSocket cap applies fleet-wide behind a proxy.** The hub limits
concurrent WebSocket connections per source address, to 8 by default. The soak
raises the limit for itself: its tenants all connect from 127.0.0.1 only
because the hub and its clients run in one process.

The same thing happens for real when a deployment terminates TLS at a reverse
proxy without setting `behind_proxy`. The hub then sees every client at the
proxy's address, and eight connections (three browser tabs from two users) use
up the cap for everyone. You see a WebSocket dial fail with 429, and the
dashboard falls back to SSE without any message. See
[`hub bootstrap --behind-proxy`](runbook.md).

**Audit appends are best-effort under concurrent load.** When several
dispatches mint leases at once, SQLite can return `database is locked` for an
audit insert. The hub reports the first failure at once, prints a summary of
later ones once a minute, and carries on. The audit trail is a compliance
record, but runs don't wait for it, so the hub stays available. Each loss is
written into the chain afterwards as an `audit.gap` row that says how many
events were lost, so under heavy concurrency the number of audit rows can be
lower than the number of events, and the gap rows account for the difference.
The soak's growth check compares two intervals and isn't affected, but keep
this in mind if you reconcile audit counts.
