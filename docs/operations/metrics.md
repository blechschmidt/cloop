# Metrics

The hub exports Prometheus metrics at `GET /metrics`, in the text exposition
format (version 0.0.4).

The catalog is declared in one file, [`pkg/hubmetrics/catalog.go`][catalog], so
that "what does this hub expose, and does anything here label by something
unbounded?" is a question you answer by reading a single page rather than by
grepping the repository. This document is the operator-facing half of that
file, and two tests keep the three in step: `TestCatalogIsDocumented` fails the
build if a metric is exported without an entry here, or described here without
being exported, and `TestEveryFamilyIsRecorded` fails it if a metric is
declared without anything in the hub that records it — so every family below
carries samples once the thing it measures has happened.

[catalog]: https://github.com/blechschmidt/cloop/blob/main/pkg/hubmetrics/catalog.go

## Scraping

The endpoint is gated on the **`audit.read`** permission and is global in
scope, not per-project. That is deliberate: the payload names every identity
the hub is accounting and what each one spends, which is oversight-grade data
of the same class the audit trail carries. A wide-open `/metrics` on a hosted
hub is a tenant roster for anyone who can reach the port.

A scraper therefore has to authenticate. Mint a service-account token holding a
role that grants `audit.read`:

```bash
cloop hub token create prometheus --role admin --expires-in 0
```

> **`admin` is currently the only role that grants `audit.read`.** That is more
> privilege than a scraper needs — the token can also mint other tokens and
> revoke sessions. Until a narrower role exists, treat the scrape credential as
> an administrative one: store it in a secret manager, give it an expiry your
> rotation actually honours (`--expires-in 90d` rather than the `0` above) and
> keep it off shared Prometheus instances. If that trade is unacceptable,
> terminate the scrape at a sidecar you control rather than handing the token
> to a multi-tenant monitoring system.

Give Prometheus the token as a bearer credential:

```yaml
scrape_configs:
  - job_name: cloop-hub
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: cloop_pat_...
    static_configs:
      - targets: ['hub.example.com:8888']
```

### `cloop serve` is not this endpoint

`cloop serve` also answers `GET /metrics`, but it serves something else
entirely: a replay of the per-run `.cloop/metrics.json` that `pkg/metrics`
writes for a single orchestrator run, keyed to one provider and model. It knows
nothing about the hub, the fleet or any tenant, and it is not backed by this
registry.

Point a hub scraper at `cloop ui`. The two are easy to confuse precisely
because they share a path.

## How to read the catalog

Two conventions carry most of the meaning.

**Counters end in `_total` and only ever rise.** Graph them with `rate()` or
`increase()`; the absolute value is only meaningful as a difference, because it
resets to zero when the hub restarts.

**Gauges are instantaneous.** Most are recomputed at scrape time by a
collector that reads live subsystem state — the executor fleet, live leases,
live sessions, key rotation progress, quota usage — rather than being
maintained incrementally. Those gauges reset and repopulate on every scrape, so
a series disappears when the object behind it does, instead of freezing at its
last value. A frozen gauge is worse than a missing one: it reads as a live
measurement and will hold an alert open forever. Two are kept incrementally by
the subsystem that owns them, because it is the only thing that sees every
change: the merge queue's depth and the egress broker's live sessions.

## Cardinality and the overflow series

Every distinct label combination is a series that lives until the process
exits. In a multi-tenant hub that makes labelling by task ID, project path or
identity a way to convert tenant activity directly into hub memory — a denial
of service any signed-in user could trigger by creating projects in a loop.

The rule in the catalog is therefore absolute: **label values come from closed
enumerations that exist in Go source**, never from user or tenant input.
`TestCatalogHasNoUnboundedLabels` enforces it.

Underneath that rule sits a ceiling, because code review is fallible. Each
metric admits at most **128** distinct label combinations
(`DefaultMaxSeriesPerMetric`). Past that, samples fold into a single series
whose every label value is `__overflow__` — no samples are lost, only their
identity — and a counter names the metric that overflowed:

```
cloop_metrics_series_dropped_total{metric="..."}
```

**This counter should be zero. A non-zero value is a bug, not a capacity
signal.** It means some call site is passing an unbounded value as a label, and
that metric has gone flat: everything past the ceiling is now folded into one
series and can no longer be broken down. Find the call site named by the
`metric` label and replace the offending label value with an enumeration.

The same counter records two other faults, distinguishable by their label:

| Label value | Meaning |
| --- | --- |
| a metric name | that metric exceeded its ceiling, or was called with the wrong number of label values |
| `collector:<name>` | that scrape-time collector panicked; the rest of the scrape completed without it |

Label values are also truncated to 64 bytes, which bounds the damage when a
long user-controlled value does reach a label. Two values differing only past
that point collapse into one series.

### The one identity-labelled exception

`cloop_quota_limit` and `cloop_quota_usage` label by `identity`. They are safe
because both are Reset before every scrape: their cardinality is the number of
identities the hub is accounting *right now*, not the number it has ever seen,
so a tenant cannot grow them by churning. Both also carry a raised but finite
ceiling of 4096 series.

## Hub clusters: which member exports what

When several `cloop ui` processes serve one control plane (a
[hub cluster](../architecture/hub-cluster.md)), scrape every member, the way
you would any replicated service. Each member's scrape then splits three ways:

**Counters are per member.** A member counts the runs it dispatched or
settled, the tokens it verified, the sessions whose end it recorded, the
requests its proxy decided. `sum()` over members is the cluster's total, and a
run that started on one member and was settled by another after the first died
is counted once at each end, as it should be.

**Gauges read from the shared database are exported by the leader only.**
Every member reads the same rows, so if each exported them, three members
would report three times the fleet under `sum()`. These come from whichever
member holds leadership, and from no other:

```
cloop_executors                           cloop_projects_registered
cloop_executor_heartbeat_age_seconds_max  cloop_quota_enforcement_enabled
cloop_secret_kek_rotation_records         cloop_quota_limit
cloop_secret_kek_rotation_active          cloop_quota_usage
cloop_sessions_live                       cloop_quota_identities
cloop_statedb_wal_bytes
```

`sum()` and `max()` over the cluster therefore both give the right answer. A
standalone hub is always its own leader. During a leadership hand-over — at
most a lease TTL, normally seconds — no member exports these, so they read as
briefly absent rather than doubled or stale; write alerts on them with a `for:`
of a minute or more.

**Gauges of per-process state are exported by every member**, and each
member's value is its own share: `cloop_secret_leases_live` (the leases that
member materialised and still holds), `cloop_egress_sessions_live` (the
sessions its broker issued), `cloop_mergequeue_depth` (its own queue) and
`cloop_writeback_pinned_bytes` (the returned work held in its memory).
`sum()` is again the cluster's; `cloop_writeback_pinned_bytes_max` is the
largest one executor holds *on that member*, so aggregate it with `max()`. `cloop_hub_disk_free_bytes` is exported by
every member too, but it is a reading rather than a share: members on one
volume each report the same number, so aggregate it with `min()` by
`volume`, never `sum()` (see [Disk](#disk)).

---

## Executor and task lifecycle

These count the harness runs the hub dispatches — a Start pressed on the
dashboard, a project created with a run, a paused run the hub resumes on its
own — and settles when they end. `executor_kind` is the driver: `localprocess`,
`container`, `remote`, `kubernetes` or `virtual`. `isolation` is the level the
workload ran at: `none`, `container`, `vm` or `remote`. Neither carries an
executor ID — a hub fronting a fleet of edge devices would turn that into one
series per device per metric.

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_executor_task_starts_total` | counter | `executor_kind`, `isolation` |
| `cloop_executor_task_completions_total` | counter | `executor_kind`, `isolation` |
| `cloop_executor_task_failures_total` | counter | `executor_kind`, `isolation`, `reason` |
| `cloop_executor_task_duration_seconds` | histogram | `executor_kind`, `isolation` |

A run is counted as started once the hub has chosen its executor, whether or
not that executor then launches it. When the run is settled it is counted once
more: as a completion if its workload exited zero, or as a failure with a
`reason`:

| `reason` | Meaning |
| --- | --- |
| `start` | it never began: the executor could not receive what the run needed (a grant, a sandbox, the source tree) or refused to launch it |
| `run` | it launched and failed — a non-zero exit, a kill nobody in cloop asked for (usually the OOM killer), an executor failure — or ended in a way its executor could not account for |
| `cancelled` | the control plane stopped it: Stop pressed, a daily budget spent, or a kill cloop requested. A run that pauses and exits zero after being told to stop is cancelled, not completed |

The distinction matters: `start` is an infrastructure or configuration fault,
`run` is usually the task's own doing, and `cancelled` is nobody's fault.
Every run the hub settles is counted exactly once more, so starts minus
completions minus failures is the runs dispatched and not yet settled: the ones
in flight, plus the rare one whose output the hub lost hold of at dispatch and
so cannot settle. A run refused before any executor was chosen — a project
bound to an executor that is not registered, or strict mode refusing the host —
never reached a driver and is not counted; the refusal is in the dashboard and
the hub's log.

The duration is observed for every run that launched (a failure at start has
none): the executor's own account of the workload, start to finish, or where
the executor keeps no such account, the time since the hub began following the
run. The buckets
span 1 second to 2 hours, because that is the real range — a run with nothing
left to do, or one that crashes on start, is over in seconds, while an agent
task on a remote sandbox runs for an hour.

In a [hub cluster](#hub-clusters-which-member-exports-what) the member that
dispatched a run counts its start and the member that settled it counts its
end — the same one, unless the run was adopted after its member died — so sum
over members.

**Task success rate**

```promql
sum(rate(cloop_executor_task_completions_total[5m]))
  / sum(rate(cloop_executor_task_starts_total[5m]))
```

**Infrastructure faults only, by driver**

```promql
sum by (executor_kind) (rate(cloop_executor_task_failures_total{reason="start"}[5m]))
```

**Runs dispatched and not yet settled**

```promql
sum(cloop_executor_task_starts_total)
  - sum(cloop_executor_task_completions_total)
  - sum(cloop_executor_task_failures_total)
```

Counters reset when a hub restarts, so read this one over a member's
lifetime.

## Executor fleet health

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_executors` | gauge | `kind`, `state` |
| `cloop_executor_heartbeat_age_seconds_max` | gauge | `kind` |
| `cloop_executor_placements_total` | counter | `result` |
| `cloop_executor_placement_failures_total` | counter | `constraint` |

`state` is `ready`, `degraded`, `unreachable`, `cordoned` or `draining`.
`result` is `placed` or `failed`. `constraint` is the `pkg/executor.Constraint`
that rejected the most candidates — the headline reason placement found
nothing, not the full per-candidate detail, which interpolates executor IDs.

`cloop_executors` counts the executors registered with the hub by the state
the liveness supervisor last recorded for each; one the supervisor has not
probed yet counts as `ready`, as placement treats it. Both fleet gauges are
read at scrape time from the shared database and exported by the
[leader only](#hub-clusters-which-member-exports-what).

The heartbeat gauge reports the *oldest* successful liveness probe per kind
rather than one series per executor. The alert that matters is "some executor
of this kind has gone quiet", and a maximum answers it in one series instead of
one per device. An executor that has never answered is aged from when it
entered its current state, so one that has been unreachable since the hub met
it still rises.

**No executor of a kind is schedulable**

```promql
sum by (kind) (cloop_executors{state="ready"}) == 0
```

**A node has gone quiet**

```promql
cloop_executor_heartbeat_age_seconds_max > 120
```

**Work is arriving that nothing can run** — this is the alert that catches a
misconfigured fleet before users report it:

```promql
rate(cloop_executor_placement_failures_total[5m]) > 0
```

## Secrets and leases

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_secret_lease_events_total` | counter | `kind`, `event` |
| `cloop_secret_leases_live` | gauge | `kind` |
| `cloop_secret_unseal_failures_total` | counter | `reason` |
| `cloop_secret_kek_rotation_records` | gauge | `phase` |
| `cloop_secret_kek_rotation_active` | gauge | — |

`kind` is the credential kind: `github_pat`, `github_app`, `kubeconfig`,
`registry`, `env`, `egress_proxy`, `local_repo`, `host_device` or
`host_interface`. `event` is `issued`, `renewed`, `revoked` or `expired`.

`cloop_secret_leases_live` counts the leases a hub process issued, still holds
and has not seen expire, with every kind present — zero included. It is per
process: a lease's material lives with the member that materialised it, so in a
cluster each member reports its own and the sum is the cluster's.

**`cloop_secret_unseal_failures_total` is the one to page on.** Any non-zero
rate means the hub can no longer read its own secrets. `reason` says which
flavour of emergency:

| `reason` | Meaning |
| --- | --- |
| `key_unknown` | ciphertext names a key-encryption key the hub has never seen |
| `key_retired` | it names a KEK that has been retired |
| `key_unavailable` | the KEK is known but cannot be opened — usually a wrong or missing passphrase |
| `seal_failed` | authenticated decryption failed: the ciphertext or its associated data has been altered |

None of these is self-healing. See the [runbook](runbook.md) for recovery.

`cloop_secret_kek_rotation_active` is 1 while a rotation is running.
**A rotation that stays at 1 across scrapes has stalled**, with records still
wrapped under the old key:

```promql
min_over_time(cloop_secret_kek_rotation_active[30m]) == 1
```

`cloop_secret_kek_rotation_records` reports progress by `phase` — `total`,
`rewrapped`, `skipped`, `failed`. Both rotation gauges read the history
`cloop hub key rotate` writes to the control-plane database, so they follow a
rotation run from the command line, and are exported by the
[leader only](#hub-clusters-which-member-exports-what). A hub that has never
rotated reports `cloop_secret_kek_rotation_active 0` and no progress. A rotation
whose process was killed stays at 1 until the next one starts — which is
exactly the stalled state the alert above is for.

## Sign-in, sessions and API tokens

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_oidc_login_total` | counter | `outcome` |
| `cloop_oidc_renewal_total` | counter | `outcome` |
| `cloop_oidc_discovery_failures_total` | counter | — |
| `cloop_sessions_created_total` | counter | — |
| `cloop_sessions_terminated_total` | counter | `reason` |
| `cloop_sessions_live` | gauge | — |
| `cloop_apitoken_auth_total` | counter | `result` |
| `cloop_apitoken_auth_failures_total` | counter | `reason` |

Sessions are deliberately unlabelled by subject. The *count* of sessions is
operational; the roster of who holds them belongs in the audit trail behind
`audit.read`, not copied into every monitoring system that touches a scrape.

A session is counted as created when a sign-in completes, and as terminated
by the call whose delete actually removed it from the session store — so a
session two requests both found expired, or a janitor pass racing a sign-out,
ends once here exactly as it does in the audit trail. `reason` on termination
is one of:

| `reason` | Meaning |
| --- | --- |
| `idle_evicted` | it went unused past the idle timeout |
| `absolute_expired` | it reached the ceiling set at sign-in |
| `self_logout` | the user signed out of it, or ended all their other sessions |
| `admin_revoked` | an operator terminated it, from the sessions panel or an offboarding |
| `idp_revoked` | the identity provider refused to renew the grant — the user was disabled there, or withdrew consent |
| `quota_evicted` | the identity's session quota ended its least recently used session to make room for a new sign-in |

`cloop hub session revoke` deletes sessions from its own process, outside any
hub's registry, so those terminations lower `cloop_sessions_live` without
appearing in `cloop_sessions_terminated_total`; the audit trail records them.

`cloop_sessions_live` counts the sessions valid at scrape time — neither past
their ceiling nor idle past the timeout, as the session store records them
(a session's last-seen time is written at most once a minute). It reads the
shared database, so it is exported by the
[leader only](#hub-clusters-which-member-exports-what), and is 0 on a hub
without sign-on.

`cloop_apitoken_auth_total` counts every verdict on a presented API token, and
`reason` on a failure is `malformed`, `not_found`, `bad_secret`, `revoked`,
`expired`, `no_roles` or `store_error`. The first six are the token's fault;
`store_error` is the hub's — its token store could not be read, and every
scraper and CI job holding a token is being turned away. A request the failure
lockout refuses before verifying anything is not counted as either. A
display-glasses link that verifies and is then refused by the rules for its
kind — a path outside the glasses views, or an owner it no longer names — is
counted as a success: the token was genuine, and what refused it was
authorization, not authentication.

`outcome` on a sign-in is `success`, `discovery_failed`, `idp_error`,
`invalid_request`, `invalid_state`, `exchange_failed`, `token_invalid`,
`session_error` or `state_error`. They separate problems with different
owners: `discovery_failed` is this hub's issuer setting, `exchange_failed` is
the client registration at the provider, `idp_error` is the provider's own
decision about the user, and `invalid_state` at any volume is somebody
replaying callbacks. A redirect to the provider is not counted until it comes
back — counting it would make the success ratio depend on how many people
opened the login page and wandered off.

**Nobody can sign in** — the alert that used to require a human to try:

```promql
rate(cloop_oidc_discovery_failures_total[5m]) > 0
```

A hub whose issuer has *never* resolved also reports `/readyz` as not ready
with `"check": "identity"`, so a Kubernetes rollout stalls instead of replacing
a working hub with one nobody can log into. Once discovery has succeeded once
the gate stays open: existing sessions keep authenticating through a later
provider outage, and dropping the hub from its Service over one would turn a
login outage into a total one. Run `cloop hub doctor` for which of the two
round trips failed and why.

`cloop_oidc_renewal_total` counts *silent* renewals: the `prompt=none` round
trip a signed-in dashboard makes from a hidden frame to re-assert its claims
when the hub holds no refresh token to do it with (see
[Silent renewal from the browser](../security/model.md#silent-renewal-from-the-browser)).
It is kept apart from `cloop_oidc_login_total` because it runs every few minutes
per open tab and would swamp the sign-in ratio. `outcome` is `ok`,
`interaction_required`, `no_session`, `not_enabled`, `idp_error`,
`discovery_failed`, `state_error`, `invalid_state`, `exchange_failed`,
`token_invalid`, `subject_mismatch` or `store_error`.

The ratio worth watching is `interaction_required` against `ok`. A hub where it
climbs is one whose users are being asked to sign in again mid-session — most
often because their browser keeps the provider's cookies out of frames, so the
provider cannot see its own session there. The remedy is on the hub side: set
`CLOOP_SECRET_KEY` and request `offline_access`, so the hub re-asserts claims
itself and the browser never has to.

```promql
rate(cloop_oidc_renewal_total{outcome="interaction_required"}[15m])
  / clamp_min(rate(cloop_oidc_renewal_total[15m]), 1e-9) > 0.2
```

A renewal that fails *inside the browser* — a provider that refuses to be
framed, a frame that never answers — never reaches the hub and is not counted
here; the dashboard shows the user a sign-in banner instead.

**Credential stuffing** — a `bad_secret` spike is a token ID that exists being
tried with wrong secrets:

```promql
rate(cloop_apitoken_auth_failures_total{reason="bad_secret"}[5m]) > 1
```

## Requests from other origins

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_cross_origin_refusals_total` | counter | `reason` |

Counts what the hub refused because a page on another origin asked for it
(Task 20394; [the threat model](../security/threat-model.md)). `reason`
is one of:

| `reason` | Meaning |
| --- | --- |
| `cross_site` | the browser sent `Sec-Fetch-Site: cross-site` on a state-changing request |
| `same_site` | `Sec-Fetch-Site: same-site` — another port of the hub's host, or a sibling subdomain |
| `unknown_fetch_site` | a `Sec-Fetch-Site` value the hub does not know, refused rather than guessed at |
| `foreign_origin` | no `Sec-Fetch-Site`, and an `Origin` that is none of the hub's own; also every refused WebSocket handshake |
| `media_type` | a state-changing request whose body is form data or `text/plain` — what a form on another site can send |
| `unknown_host` | a hub without sign-in was addressed by a host name it does not answer to: the shape DNS rebinding takes |

The origin and host are in the audit trail
([`request.origin_refused`](../reference/audit-events.md#request),
[`request.host_refused`](../reference/audit-events.md#request)), not here: the
sender chooses both. A burst of `foreign_origin` or `media_type` right after a
proxy change usually means the proxy no longer passes the hub its own origin —
see [`ui.trusted_proxies`](../reference/configuration.md#tls).

```promql
sum by (reason) (rate(cloop_cross_origin_refusals_total[5m])) > 0
```

## Write-back

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_writeback_bundles_total` | counter | `result` |
| `cloop_writeback_rejections_total` | counter | `reason` |

`result` is `accepted`, `rejected` or `unavailable`, and the distinction is the
one the code makes: a **rejection** is the hub refusing what a sandbox
returned, an **outage** (`unavailable`) is the hub being unable to find out.
They page differently — the first is a misbehaving or compromised sandbox, the
second is broken infrastructure.

`reason` is an `executor.WriteBackReason*` code. The prose refusal is in the
audit trail rather than here, because it interpolates branch names and commit
SHAs.

### Returned work held in memory

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_writeback_pinned_bytes` | gauge | — |
| `cloop_writeback_pinned_bytes_max` | gauge | — |
| `cloop_writeback_frame_refusals_total` | counter | `reason` |

A remote executor returns two things the hub holds in memory until it collects
them: a write-back bundle, assembled from result chunks, and a seeded run's
project-state document. `cloop_writeback_pinned_bytes` is everything this hub
process holds, bounded by
[`executors.remote.max_pinned_writeback_total_bytes`](../reference/configuration.md#returned-work-held-in-memory);
`cloop_writeback_pinned_bytes_max` is the most any single executor holds,
against its own `max_pinned_writeback_bytes` budget. Both count what the budget
counts: the bytes held, plus 64 for each bundle chunk that holds them, so a
256 KiB-chunked bundle reads a fortieth of a percent above its size. Neither is
labelled by executor — a fleet of devices is the unbounded set the catalog's rule exists
for — so the max is what tells you one device is close to its budget. Both are
per process: in a hub cluster each member holds what reached it.

Collected work leaves at once, so on a healthy hub both sit near zero between
runs and rise only while a bundle is in flight. A level that stays up is work
nobody is collecting — it is let go of 15 minutes after its run ended — or a
device holding transfers open:

```promql
max(cloop_writeback_pinned_bytes_max) > 0.8 * 268435456   # 80% of the default budget
```

`cloop_writeback_frame_refusals_total` counts result frames refused before
their bytes were kept (Task 20399):

| `reason` | Meaning |
| --- | --- |
| `late` | a chunk, result or project-state document for a handle that had already reported its final status, or a chunk or result after the write-back closed with its result frame |
| `not_requested` | a chunk for a handle whose spec asked for no bundle, a result for one that asked for no write-back, or a project-state document for a run that was not seeded |
| `over_cap` | a chunk that took the bundle past the cap the handle's spec asked for |
| `executor_budget` | holding it would take the executor past `max_pinned_writeback_bytes` |
| `process_budget` | holding it would take the hub process past `max_pinned_writeback_total_bytes` |

An honest agent sends chunks, then the result, then the final status, and
nothing after, so **any** `late` or `not_requested` is a device that is broken
or compromised; alert on it and look at which executor in the hub's log. The
two budget reasons are capacity: the refused run's journal names the limit and
how much was held.

```promql
sum by (reason) (rate(cloop_writeback_frame_refusals_total{reason=~"late|not_requested|over_cap"}[5m])) > 0
```

## Merge queue

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_mergequeue_depth` | gauge | — |
| `cloop_mergequeue_merges_total` | counter | `outcome` |

`outcome` is `clean`, `auto_resolved`, `unresolved` or `error`.

The queue is serial, so **sustained depth is the integration path falling
behind task completion**:

```promql
min_over_time(cloop_mergequeue_depth[15m]) > 5
```

A rising `unresolved` rate means the AI conflict resolver is handing conflicts
back for a human.

## Git interception proxy

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_gitproxy_pushes_total` | counter | `result` |
| `cloop_gitproxy_push_denials_total` | counter | `reason` |
| `cloop_gitproxy_anonymous_requests_total` | counter | — |

This is the boundary a sandbox pushes through, so its denial counter is a
security signal and not only an operational one. `reason` is
`ref_not_allowed`, `delete_denied`, `create_denied`, `update_denied`,
`no_write`, `too_many_commands` or `push_cert`. `no_write` is part of the
vocabulary but no code path produces it today: a session that may not push is
refused before any command is parsed — at the receive-pack advertisement, or at
the push itself when a client skips discovery — so that refusal is a
`gitproxy.rejected` audit row and appears in neither counter. The
counters see pushes only — fetches, sessions, and requests for a repository
outside a session's scope are in the audit trail and nowhere here.

`cloop_gitproxy_anonymous_requests_total` counts requests that presented no
credential at all. They are not written to the audit trail: nearly all of them
are git's own authentication challenge (a bare request, answered 401, before git
retries with the lease's session credential), and the rest are anything else
reaching the proxy's port. It tracks the proxy's own traffic closely; a rate far
above it is something other than git knocking.

**A sandbox probing the allowlist**

```promql
rate(cloop_gitproxy_push_denials_total{reason="ref_not_allowed"}[5m]) > 0.1
```

## Kubernetes access monitor

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_kubeguard_requests_total` | counter | `result` |
| `cloop_kubeguard_denials_total` | counter | `reason` |

Same shape and same reasoning as the git proxy above: this is the boundary a
sandbox's `kubectl` passes through, so the denial counter says whether the
boundary is being tested. `result` is `allowed` or `denied`; `reason` is
`verb_not_allowed`, `namespace_not_allowed`, `cluster_scope`,
`resource_not_allowed`, `dangerous_subresource`, `non_resource_path`,
`protocol_upgrade`, `body_too_large` or `unauthenticated`. Sustained
`verb_not_allowed` is a workload expecting write access it was not granted;
`dangerous_subresource` is an attempt to open a shell inside a pod.

A proxy-side failure — an unreachable cluster, an unusable credential — is
counted as **neither** allowed nor denied, so the denial rate does not lie in
exactly the situation an operator is paging on.

**A workload expecting write access it was not granted**

```promql
rate(cloop_kubeguard_denials_total{reason="verb_not_allowed"}[5m]) > 0.1
```

**An attempt to get a shell in a pod.** The monitor refuses `exec`, `attach`,
`portforward` and `proxy` for every verb, so this should be flat at zero:

```promql
rate(cloop_kubeguard_denials_total{reason="dangerous_subresource"}[5m]) > 0
```

See [the Kubernetes access monitor](../architecture/kubernetes-access.md) for
what each reason means.

## Egress broker

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_egress_requests_total` | counter | `result` |
| `cloop_egress_denials_total` | counter | `reason` |
| `cloop_egress_bytes_total` | counter | `direction` |
| `cloop_egress_sessions_live` | gauge | — |

The broker records these itself, from the same typed error each audit row is
derived from, so a verdict cannot reach one and miss the other. All four are
per process: a session lives in the broker that issued it, and so do its
verdicts and its bytes. On a hub they come from the proxy `cloop ui` hosts when
[`executors.egress`](../reference/configuration.md#scoped-network-egress) is
enabled, and move with the runs it issues sessions to; in a hub cluster every
member hosts its own proxy and reports its own, and the cluster's is the sum.
`cloop egress test` runs a proxy of its own, in its own process, for the length
of one test, and its samples stay in that process. A hub with the section
disabled exports the families with no samples.

`cloop_egress_requests_total` counts the requests through the proxy that
reached a policy verdict: a CONNECT tunnel opened or refused, a plain-HTTP
exchange forwarded or refused. A request that failed for want of DNS or a
route, or was malformed, is neither allowed nor denied, so the denial rate does
not move in exactly the situation an operator is paging on. A request with no
valid credential is refused with 407 and counted nowhere — like the audit
trail, the count starts at an authenticated session — but one on a session that
is spent, expired or past its quota, is a verdict and is counted.

`cloop_egress_denials_total` counts every refusal the broker makes, which is
more than the denied requests. `no_grant`, `revoked` and an expired grant's
`expired` refuse a *session*, when one is asked for and before any request
exists. `quota_exhausted` and `expired` also cut a transfer the broker had
allowed, when a budget is spent or a session's TTL lapses inside an open tunnel
— that request already has its `allowed` sample, so only the denial is added.

| `reason` | Meaning |
| --- | --- |
| `no_grant` | no active grant targets the executor or project asking for a session |
| `revoked` | the grant that targets it has been revoked |
| `expired` | the grant, or the session, is past its TTL |
| `host_not_allowed` | the destination is outside the grant's host allowlist and every allowed CIDR |
| `port_not_allowed` | the destination port is outside the grant's port allowlist |
| `method_not_allowed` | the plain-HTTP method is outside the grant's method allowlist |
| `destination_blocked` | the SSRF guard refused a loopback, private, link-local, multicast or unspecified address no allowed CIDR names |
| `quota_exhausted` | the session's upload or download budget is spent |

`direction` on `cloop_egress_bytes_total` is `up` (from the sandbox) or
`down` (to it), and includes the bytes of a transfer its quota then cut — they
crossed the control plane all the same. `cloop_egress_sessions_live` counts the
sessions a process has issued and not yet closed: on a hub, roughly one per run
holding a grant, since a session is renewed for as long as its run lives and
closed when it ends. An expired one is closed within the proxy's reap interval.

`destination_blocked` is the one to alert on: a sustained rate of it is a
sandbox trying to reach the hub's own network.

```promql
rate(cloop_egress_denials_total{reason="destination_blocked"}[5m]) > 0
```

## Sessions restored with an adopted run

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_proxy_session_restores_total` | counter | `kind`, `outcome` |

When a hub process adopts a device run another stopped serving — a restart in
the same directory, or a cluster member that died — it brings back what the
run's lease feeds (Task 20383): the run's git proxy, Kubernetes monitor and
egress sessions, under the ids and tokens the workload already holds, and the
GitHub App token slots that keep its tokens alive past GitHub's hour. Each one
it tries is counted here, by the process that adopted the run. Since Task 20390
a CI relay session whose holder stopped is restored by the process receiving
the job's next call, and counted by it under `kind` `ci` (its `refused` means
its rule was deleted, disabled or no longer admits the pipeline). `kind` is
`git`, `kube`, `egress`, `app_token` or `ci`.

| `outcome` | Meaning |
| --- | --- |
| `restored` | served again by this process; the workload noticed nothing |
| `refused` | will not come back: its grant was revoked or expired while no process held it, its recorded scope is wider than the grant or this hub's proxy policy allow now, its upstream is not the forge this hub's git proxy fronts, or this process runs no proxy to serve it. Closed with the reason |
| `expired` | lapsed while no process held it |
| `lost` | another process restored it first, or took it — or its lease — over before a retry; or the lease was handed over or released while it waited |
| `failed` | its upstream credential could not be re-derived for a reason that may pass — the store busy, GitHub unreachable. Held by this process and retried every lease keepalive tick (egress: every 30 seconds), and at once when the workload's next request presents it |

After a restart, `refused` and `expired` are the ones to read: each is a
workload that gets a 401 on its next git, kubectl or proxied request, and the
session's `*.session_closed` or `egress.close` row says why. A rising `failed`
that does not turn into `restored` is GitHub out of reach from the hub.

```promql
sum by (kind, outcome) (increase(cloop_proxy_session_restores_total[1h]))
```

## Quotas and admission control

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_quota_enforcement_enabled` | gauge | — |
| `cloop_quota_limit` | gauge | `identity`, `resource` |
| `cloop_quota_usage` | gauge | `identity`, `resource` |
| `cloop_quota_denials_total` | counter | `resource` |
| `cloop_quota_identities` | gauge | — |
| `cloop_projects_registered` | gauge | — |

`resource` is a `quota.Resource` — `max_projects`, `max_executors`,
`max_sessions`, `max_concurrent_tasks` and the daily budgets.

These names and label schemas predate the registry and are preserved exactly,
because operator scrape configs and recording rules are already written against
them. The gauges describe the policy, the usage the members' enforcers share
through the database and the project registry, so a cluster exports them from
its [leader only](#hub-clusters-which-member-exports-what);
`cloop_quota_denials_total` is each member's own refusals, exported by all of
them.

**Identities near their ceiling** — the alert that gives a tenant warning
before admission starts failing:

```promql
cloop_quota_usage / cloop_quota_limit > 0.9
```

**Admission is actually refusing work**

```promql
sum by (resource) (rate(cloop_quota_denials_total[5m])) > 0
```

## Disk

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_hub_disk_free_bytes` | gauge | `volume` |

The free space each hub process could still write on the volumes it writes to
(Task 20381): the one holding its control-plane `.cloop`, where `state.db`
lives, and those of the projects registered with it, one sample per
filesystem. `volume` is the mount point. Free means writable by this process:
a hub running as root counts the blocks the filesystem reserves for root, an
unprivileged one does not.

Runs pause before their next task or evolve round while a volume they write to
is below `orchestrator.min_free_disk_mb` (default 1 GiB), and resume by
themselves once it is back above the floor plus a tenth; `cloop hub doctor`'s
`storage.free_space` finding warns below twice the floor and fails below it.
Alert before the floor, not at it:

```promql
min by (volume) (cloop_hub_disk_free_bytes) < 2 * 1073741824
```

Every member exports it for its own disk, so members sharing a volume report
the same reading; `min()` by volume is the answer, `sum()` is not. The series
set resets at every scrape and is capped at 32 volumes.

## Control-plane database

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_statedb_wal_bytes` | gauge | — |

The size of the hub database's write-ahead log, `.cloop/state.db-wal`, read at
scrape time (Task 20392). Every write passes through the log before a
checkpoint copies it into `state.db`, and SQLite never shrinks the file on its
own: a burst — a bulk delete by row retention or an audit prune, a VACUUM,
which writes the whole database through it — used to leave it at that size for
as long as the hub ran. Now every read-write connection trims it to 64 MiB when
it starts the log over, and the leader's janitor truncates it after each
retention pass and within a minute of finding it larger.

So the steady state is a few megabytes, with spikes during large writes that
come back down within minutes. A log that stays over 64 MiB is one something is
holding: a connection still reading from it (the leader's checkpoint reports
"busy" and retries every minute), or writers that all predate the limit. The
[runbook](runbook.md#the-write-ahead-log) says how to tell which.

```promql
cloop_statedb_wal_bytes > 64 * 1048576
```

with a `for:` of half an hour, which no single burst outlasts. It is a gauge of
the shared database's directory, so the cluster leader alone exports it; a hub
with no database yet exports nothing.

## Registry self-monitoring

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_metrics_series_dropped_total` | counter | `metric` |

Described under [Cardinality and the overflow
series](#cardinality-and-the-overflow-series). It should be zero; any non-zero
value is a bug in instrumentation.

```promql
cloop_metrics_series_dropped_total > 0
```

## Adding a metric

1. Declare it in `pkg/hubmetrics/catalog.go`, never at the call site. The point
   is that the whole hub's label schema stays reviewable in one file.
2. Label values must come from a closed enumeration declared in Go source. If
   you cannot point at the constant block the values come from, the label is
   unbounded and does not belong.
3. Counters end in `_total`; histograms name their unit.
4. Record it in the same change: call `Inc`, `Add`, `Set` or `Observe` on it
   where the event happens, or name it in the `Families` of a scrape-time
   collector registered in `pkg/ui/hubmetrics.go`. `TestEveryFamilyIsRecorded`
   fails the build for a family nothing records, because one that renders with
   no samples is a family every alert written against it silently ignores.
5. If it is a gauge read from the shared database, export it from the cluster
   leader only (`metricsScrape.leader`), so that `sum()` over members does not
   multiply it.
6. Add a row to this page. `TestCatalogIsDocumented` fails the build otherwise.
