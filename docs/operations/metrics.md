# Metrics

The hub exports Prometheus metrics at `GET /metrics`, in the text exposition
format (version 0.0.4).

The catalog is declared in one file, [`pkg/hubmetrics/catalog.go`][catalog], so
that "what does this hub expose, and does anything here label by something
unbounded?" is a question you answer by reading a single page rather than by
grepping the repository. This document is the operator-facing half of that
file, and a test keeps the two in step: `TestCatalogIsDocumented` fails the
build if a metric is exported without an entry here, or described here without
being exported.

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

**Gauges are instantaneous.** Several are recomputed at scrape time by a
collector that reads live subsystem state — the executor fleet, the merge
queue, live leases, quota usage — rather than being maintained incrementally.
Those gauges reset and repopulate on every scrape, so a series disappears when
the object behind it does, instead of freezing at its last value. A frozen
gauge is worse than a missing one: it reads as a live measurement and will hold
an alert open forever.

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

## Declared but not yet recorded

Every metric below is registered, so every one appears in a scrape with its
`HELP` and `TYPE`. Not all of them have a call site yet: the following families
will render with no samples until the subsystem that owns them is instrumented.

<!-- Keep in step with the call sites; see "Adding a metric" below. -->

```
cloop_executor_task_starts_total          cloop_sessions_created_total
cloop_executor_task_completions_total     cloop_sessions_terminated_total
cloop_executor_task_failures_total        cloop_sessions_live
cloop_executor_task_duration_seconds      cloop_apitoken_auth_total
cloop_executors                           cloop_apitoken_auth_failures_total
cloop_executor_heartbeat_age_seconds_max  cloop_egress_requests_total
cloop_secret_leases_live                  cloop_egress_denials_total
cloop_secret_kek_rotation_records         cloop_egress_bytes_total
cloop_secret_kek_rotation_active          cloop_egress_sessions_live
```

An alert written against one of these will never fire — not because the
condition is never met, but because the series is empty. Check here before
relying on a metric you have not seen data for. The distinction is deliberate:
a registered-but-silent family tells you the hub knows about the measurement
and has not taken it, which is a different and more useful statement than the
metric being absent entirely.

### The one identity-labelled exception

`cloop_quota_limit` and `cloop_quota_usage` label by `identity`. They are safe
because both are Reset before every scrape: their cardinality is the number of
identities the hub is accounting *right now*, not the number it has ever seen,
so a tenant cannot grow them by churning. Both also carry a raised but finite
ceiling of 4096 series.

---

## Executor and task lifecycle

`executor_kind` is the driver (`local`, `container`, `kubernetes`, `remote`);
`isolation` is the level the workload ran at. Neither carries an executor ID —
a hub fronting a fleet of edge devices would turn that into one series per
device per metric.

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_executor_task_starts_total` | counter | `executor_kind`, `isolation` |
| `cloop_executor_task_completions_total` | counter | `executor_kind`, `isolation` |
| `cloop_executor_task_failures_total` | counter | `executor_kind`, `isolation`, `reason` |
| `cloop_executor_task_duration_seconds` | histogram | `executor_kind`, `isolation` |

`reason` is `start` (the executor refused to launch the workload), `run` (it
launched and failed), or `cancelled` (the control plane withdrew it). The
distinction matters: `start` is an infrastructure fault, `run` is usually the
task's own doing.

The duration histogram's buckets span 1 second to 2 hours, because that is the
real range — a `cloop suggest` subcommand returns in seconds while an agent
task on a remote sandbox runs for an hour.

**Task success rate**

```promql
sum(rate(cloop_executor_task_completions_total[5m]))
  / sum(rate(cloop_executor_task_starts_total[5m]))
```

**Infrastructure faults only, by driver**

```promql
sum by (executor_kind) (rate(cloop_executor_task_failures_total{reason="start"}[5m]))
```

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

The heartbeat gauge reports the *oldest* successful liveness probe per kind
rather than one series per executor. The alert that matters is "some executor
of this kind has gone quiet", and a maximum answers it in one series instead of
one per device.

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

`kind` is the credential kind (GitHub repo, PAT, kubeconfig, egress, …).
`event` is `issued`, `renewed`, `revoked` or `expired`.

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
`rewrapped`, `skipped`, `failed`.

## Sessions and API tokens

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_sessions_created_total` | counter | — |
| `cloop_sessions_terminated_total` | counter | `reason` |
| `cloop_sessions_live` | gauge | — |
| `cloop_apitoken_auth_total` | counter | `result` |
| `cloop_apitoken_auth_failures_total` | counter | `reason` |

Sessions are deliberately unlabelled by subject. The *count* of sessions is
operational; the roster of who holds them belongs in the audit trail behind
`audit.read`, not copied into every monitoring system that touches a scrape.

`reason` on termination is `idle_evicted`, `absolute_expired`, `admin_revoked`
or `self_logout`. On token failure it is `malformed`, `not_found`,
`bad_secret`, `revoked`, `expired` or `no_roles`.

**Credential stuffing** — a `bad_secret` spike is a token ID that exists being
tried with wrong secrets:

```promql
rate(cloop_apitoken_auth_failures_total{reason="bad_secret"}[5m]) > 1
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

This is the boundary a sandbox pushes through, so its denial counter is a
security signal and not only an operational one. `reason` is
`ref_not_allowed`, `delete_denied`, `create_denied`, `update_denied`,
`no_write`, `too_many_commands` or `push_cert`.

**A sandbox probing the allowlist**

```promql
rate(cloop_gitproxy_push_denials_total{reason="ref_not_allowed"}[5m]) > 0.1
```

## Egress broker

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_egress_requests_total` | counter | `result` |
| `cloop_egress_denials_total` | counter | `reason` |
| `cloop_egress_bytes_total` | counter | `direction` |
| `cloop_egress_sessions_live` | gauge | — |

`direction` is `up` or `down`. The intended `reason` vocabulary is `no_grant`,
`revoked`, `expired`, `host_not_allowed`, `port_not_allowed`,
`method_not_allowed`, `destination_blocked` and `quota_exhausted` — but note
that all four egress metrics are in the [not yet
recorded](#declared-but-not-yet-recorded) list, and only the five refusals the
broker already names in source (`expired`, `host_not_allowed`,
`port_not_allowed`, `method_not_allowed`, `destination_blocked`) exist as
values today. The other three are reserved by the catalog, not yet implemented.

`destination_blocked` is the SSRF guard refusing a link-local or private
address. Once the metric is recorded, a sustained rate of it is a sandbox
trying to reach the hub's own network:

```promql
rate(cloop_egress_denials_total{reason="destination_blocked"}[5m]) > 0
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
4. Add a row to this page. `TestCatalogIsDocumented` fails the build otherwise.
