# Metrics

The hub exports Prometheus metrics at `GET /metrics`, in the text exposition
format (version 0.0.4).

Every metric is declared in one file, [`pkg/hubmetrics/catalog.go`][catalog],
so you can see everything a hub exposes, and check that no label takes
unbounded values, by reading that one file. This page is the operator's guide
to it. Two tests keep the catalog, this page and the code in step:
`TestCatalogIsDocumented` fails the build if a metric is exported but not
described here, or described here but not exported, and
`TestEveryFamilyIsRecorded` fails it if a metric is declared but nothing in the
hub records it. So every family below has samples once the thing it measures
has happened.

[catalog]: https://github.com/blechschmidt/cloop/blob/main/pkg/hubmetrics/catalog.go

## Scraping

The endpoint requires the `audit.read` permission at hub-wide scope, not per
project. The response names every identity the hub accounts for and what each
one spends, the same kind of oversight data the audit trail holds. An open
`/metrics` on a hosted hub would give anyone who can reach the port a list of
its tenants.

So a scraper has to authenticate. Create a service-account token with a role
that grants `audit.read`:

```bash
cloop hub token create prometheus --role admin --expires-in 0
```

> **`admin` is currently the only role that grants `audit.read`.** That gives a
> scraper more privilege than it needs: the token can also mint other tokens
> and revoke sessions. Until a narrower role exists, treat the scrape credential
> as an administrator's. Keep it in a secret manager, give it an expiry that
> your rotation keeps to (`--expires-in 90d` instead of the `0` above), and keep
> it off shared Prometheus instances. If that isn't acceptable, end the scrape
> at a sidecar you control instead of giving the token to a multi-tenant
> monitoring system.

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

`cloop serve` also answers `GET /metrics`, but with something different: the
per-run `.cloop/metrics.json` that `pkg/metrics` writes for a single
orchestrator run, for one provider and model. It knows nothing about the hub,
the fleet or tenants, and doesn't come from this registry.

Point a hub scraper at `cloop ui`. The two are easy to confuse because they use
the same path.

## How to read the catalog

Two conventions apply throughout.

**Counters end in `_total` and only ever go up.** Graph them with `rate()` or
`increase()`. The absolute value only means something as a difference, because
it resets to zero when the hub restarts.

**Gauges are instantaneous.** Most are recomputed at scrape time by a
collector that reads the live state of a subsystem (the executor fleet, live
leases, live sessions, key rotation progress, quota usage). These gauges are
reset and refilled on every scrape, so a series disappears when the object
behind it does. It doesn't freeze at its last value, which would look like a
live measurement and could keep an alert firing forever. Two gauges are instead
updated incrementally by the subsystem that owns them, because only that
subsystem sees every change: the merge queue's depth and the egress broker's
live sessions.

## Cardinality and the overflow series

Every distinct label combination is a series that stays in memory until the
process exits. In a multi-tenant hub, a label holding a task ID, project path
or identity would turn tenant activity directly into hub memory use: any
signed-in user could exhaust it by creating projects in a loop.

So the catalog has a strict rule: label values come from closed enumerations in
the Go source, never from user or tenant input.
`TestCatalogHasNoUnboundedLabels` enforces it.

Because code review can miss things, there is also a ceiling. Each metric
accepts at most 128 distinct label combinations (`DefaultMaxSeriesPerMetric`).
Beyond that, samples are folded into a single series whose label values are
all `__overflow__`. No samples are lost, only their labels, and a counter names
the metric that overflowed:

```
cloop_metrics_series_dropped_total{metric="..."}
```

This counter should be zero. A non-zero value means a bug, not a capacity
problem: some call site is passing an unbounded value as a label. Everything
past the ceiling for that metric is folded into one series and can no longer
be broken down. Find the call site for the metric named in the `metric` label
and replace the label value with an enumeration.

The same counter records two other faults, told apart by the label value:

| Label value | Meaning |
| --- | --- |
| a metric name | that metric exceeded its ceiling, or was called with the wrong number of label values |
| `collector:<name>` | that scrape-time collector panicked. The rest of the scrape completed without it |

Label values are also cut to 64 bytes, which limits the damage when a long
user-controlled value does reach a label. Two values that differ only after the
first 64 bytes become one series.

### The one identity-labelled exception

`cloop_quota_limit` and `cloop_quota_usage` have an `identity` label. This is
safe because both are reset before every scrape: their series count is the
number of identities the hub accounts for at that moment, not every identity it
has ever seen, so a tenant can't inflate it by churning through identities.
Both also have a higher, but still finite, ceiling of 4096 series.

### Labels from the operator's configuration

`sink`, on the [audit forwarding](#forwarding-the-trail-off-the-box) families
and on [approval notifications](#approval-notifications), is the only label
whose values are not declared in the Go source. It is still bounded: its values
are the names of the sinks in `audit.forward.sinks` (at most 16) or of the
webhooks in `notifications.webhooks` (at most 8). Each is a short lower-case
name that only whoever writes the hub's configuration can choose, never a
tenant or a request. The two audit gauges are reset on every scrape, so they
name only the sinks currently configured. The counters keep a series for a sink
that was renamed or removed since the process started.

## Hub clusters: which member exports what

When several `cloop ui` processes serve one control plane (a
[hub cluster](../architecture/hub-cluster.md)), scrape every member, as you
would any replicated service. The metrics in each member's scrape fall into
three groups.

**Counters are per member.** A member counts the runs it dispatched or
settled, the tokens it verified, the sessions whose end it recorded and the
requests its proxy decided. `sum()` over members gives the cluster's total. A
run that started on one member and was settled by another after the first died
is counted once at each end.

**Gauges read from the shared database are exported by the leader only.**
Every member reads the same rows, so if each exported them, `sum()` over three
members would report three times the fleet. These come from the current leader
and from no other member:

```
cloop_executors                           cloop_projects_registered
cloop_executor_heartbeat_age_seconds_max  cloop_quota_enforcement_enabled
cloop_secret_kek_rotation_records         cloop_quota_limit
cloop_secret_kek_rotation_active          cloop_quota_usage
cloop_sessions_live                       cloop_quota_identities
cloop_statedb_wal_bytes                   cloop_audit_forward_lag_seconds
cloop_audit_forward_backlog_rows          cloop_hub_ca_not_after_timestamp_seconds
cloop_hub_ca_rotation_phase               cloop_hub_ca_rotation_step_age_seconds
cloop_hub_ca_runs_blocking                cloop_hub_ca_members_behind
cloop_knowledge_index_documents           cloop_knowledge_index_chunks
cloop_knowledge_index_bytes               cloop_knowledge_index_vectors
```

So `sum()` and `max()` over the cluster both give the right answer. A
standalone hub is always its own leader. During a leadership hand-over (at most
a lease TTL, normally a few seconds) no member exports these, so they are
briefly absent, never doubled or stale. Give alerts on them a `for:` of a
minute or more.

**Gauges of per-process state are exported by every member**, each reporting
its own share: `cloop_secret_leases_live` (the leases that member materialised
and still holds), `cloop_egress_sessions_live` (the sessions its broker
issued), `cloop_mergequeue_depth` (its own queue) and
`cloop_writeback_pinned_bytes` (the returned work held in its memory). Again,
`sum()` gives the cluster's value. `cloop_writeback_pinned_bytes_max` is the
most that one executor holds on that member, so aggregate it with `max()`.
Every member also exports `cloop_hub_disk_free_bytes`, but it is a reading,
not a share: members on the same volume all report the same number, so
aggregate it with `min()` by `volume`, never `sum()` (see [Disk](#disk)).

---

## Executor and task lifecycle

These count the harness runs the hub dispatches (**Start** pressed on the
dashboard, a project created with a run, a paused run the hub resumes by
itself) and settles when they end. `executor_kind` is the driver:
`localprocess`, `container`, `remote`, `kubernetes` or `virtual`. `isolation`
is the isolation level the workload ran at: `none`, `container`, `vm` or
`remote`. Neither label carries an executor ID, which on a hub with a fleet of
edge devices would create one series per device per metric.

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_executor_task_starts_total` | counter | `executor_kind`, `isolation` |
| `cloop_executor_task_completions_total` | counter | `executor_kind`, `isolation` |
| `cloop_executor_task_failures_total` | counter | `executor_kind`, `isolation`, `reason` |
| `cloop_executor_task_duration_seconds` | histogram | `executor_kind`, `isolation` |

A run counts as started once the hub has chosen its executor, whether or not
the executor then launches it. When the run is settled, it is counted once
more: as a completion if its workload exited with status zero, or as a failure
with a `reason`:

| `reason` | Meaning |
| --- | --- |
| `start` | it never began: the executor could not receive what the run needed (a grant, a sandbox, the source tree) or refused to launch it |
| `run` | it launched and then failed (a non-zero exit, a kill that cloop did not request, usually the OOM killer, or an executor failure), or it ended in a way its executor could not account for |
| `cancelled` | the control plane stopped it: **Stop** pressed, a daily budget spent, or a kill cloop requested. A run that pauses and exits zero after being told to stop counts as cancelled, not completed |
| `disk_limit` | its executor stopped it because the workspace grew past its disk limit (`resources.disk` in `.cloop/sandbox.yaml`, or an operator's disk ceiling). The project is paused with `disk_limit`; see [the sandbox reference](../reference/sandbox.md#resourcesdisk-and-the-workspace) |

`start` points to an infrastructure or configuration fault, `run` is usually
caused by the task itself, `cancelled` is nobody's fault, and `disk_limit` is a
limit working as intended.

Every run the hub settles is counted once more, so starts minus completions
minus failures is the number of runs dispatched and not yet settled: the ones
in flight, plus the rare run whose output the hub lost track of at dispatch and
so can't settle. A run refused before any executor was chosen (a project bound
to an executor that isn't registered, or strict mode refusing the host) never
reached a driver and isn't counted. The refusal appears in the dashboard and
the hub's log.

The duration is recorded for every run that launched (a failure at start has
none). It is the executor's own measurement of the workload from start to
finish or, if the executor doesn't keep one, the time since the hub began
following the run. The buckets span 1 second to 2 hours, which covers the real
range: a run with nothing left to do, or one that crashes on start, is over in
seconds, while an agent task on a remote sandbox can take an hour.

In a [hub cluster](#hub-clusters-which-member-exports-what), the member that
dispatched a run counts its start and the member that settled it counts its
end. They are the same member unless the run was adopted after its member
died, so sum over members.

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
that rejected the most candidates: the main reason placement found nothing.
The full per-candidate detail isn't used, because it includes executor IDs.

`cloop_executors` counts the executors registered with the hub, by the state
the liveness supervisor last recorded for each. An executor the supervisor
hasn't probed yet counts as `ready`, which is how placement treats it. Both
fleet gauges are read from the shared database at scrape time and exported by
the [leader only](#hub-clusters-which-member-exports-what).

The heartbeat gauge reports the age of the *oldest* successful liveness probe
per kind, not one series per executor. The useful alert is "some executor of
this kind has gone quiet", and a maximum answers that with one series instead
of one per device. For an executor that has never answered, the age counts from
when it entered its current state, so one that has been unreachable since the
hub first saw it still shows a rising age.

**No executor of a kind is schedulable**

```promql
sum by (kind) (cloop_executors{state="ready"}) == 0
```

**A node has gone quiet**

```promql
cloop_executor_heartbeat_age_seconds_max > 120
```

**Work is arriving that nothing can run.** This alert catches a misconfigured
fleet before users report it:

```promql
rate(cloop_executor_placement_failures_total[5m]) > 0
```

### Isolation probes

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_executor_isolation_probes_total` | counter | `point`, `status` |

One sample per isolation probe the hub runs under an executor's runtime.
`point` is what triggered the probe: `reconcile`, `hello`, `runtime_change`,
`daily` or `manual`. `status` is the result for the runtime's claim:
`verified`; `contradicted` (the probe found less isolation than the runtime's
name claims, and projects that require isolation are refused there);
`unverified` (inconclusive); or `failed` (the probe could not run). Each member
counts the probes it ran, so sum across members.

**A runtime is not what its name says.** Page on this. The executor's card and
`cloop hub doctor` show the runtime and the evidence:

```promql
increase(cloop_executor_isolation_probes_total{status="contradicted"}[1d]) > 0
```

### Executor pools

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_executor_pool_demand` | gauge | none |
| `cloop_executor_pool_runners` | gauge | `state` |
| `cloop_executor_pool_mint_refusals_total` | counter | `reason` |
| `cloop_executor_pool_runners_minted_total` | counter | none |
| `cloop_executor_pool_runners_retired_total` | counter | `reason` |

An executor pool is a set of runners a controller starts on demand; each takes
one run and is retired. `cloop_executor_pool_demand` is the number of runs
waiting in the pools' queues that their pools may see and run, summed over
pools: what the controllers are being asked to meet. `cloop_executor_pool_runners`
counts the pools' runners by `state`: `busy` (handed a run), `idle` (enrolled,
waiting for one) and `pending` (a runner token minted and not yet redeemed).
Both gauges are read from the shared database and exported by the cluster
leader only. Neither is labelled by pool: each controller's feed carries its
own pool's numbers.

`cloop_executor_pool_mint_refusals_total` counts the runner-token requests the
hub refused, by `reason`: `max_runners` (the pool would exceed it),
`revoked` (the pool or the controller's credential was revoked),
`cordoned` (an administrator holds the pool), `invalid_credential` or
`invalid_request`. The minted and retired counters
count runners in and out; a retired runner's `reason` is `run_settled`,
`left_idle` (it went offline before it was handed a run), `idle_timeout`,
`pool_revoked`, `credential_revoked` (the controller credential that minted it
was revoked), `lost` (its run was lost with it), `start_failed` (a queued run
could not be started on it), `token_expired` (minted and never redeemed),
`scaled_down` (its controller retired it while it was idle or not yet
enrolled) or `other`. Each member counts what it did.

**Runs wait and no runner comes.** The controller is down, or cannot start
runners:

```promql
cloop_executor_pool_demand > 0 and sum(cloop_executor_pool_runners) == 0
```

**A controller keeps asking past its pool's max_runners**, or with a revoked
credential:

```promql
increase(cloop_executor_pool_mint_refusals_total[15m]) > 10
```

## Secrets and leases

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_secret_lease_events_total` | counter | `kind`, `event` |
| `cloop_secret_leases_live` | gauge | `kind` |
| `cloop_secret_unseal_failures_total` | counter | `reason` |
| `cloop_secret_kek_rotation_records` | gauge | `phase` |
| `cloop_secret_kek_rotation_active` | gauge | none |

`kind` is the credential kind: `github_pat`, `github_app`, `kubeconfig`,
`registry`, `env`, `egress_proxy`, `local_repo`, `host_device` or
`host_interface`. `event` is `issued`, `renewed`, `revoked` or `expired`.

`cloop_secret_leases_live` counts the leases a hub process issued, still holds
and hasn't seen expire, with a series for every kind, including those at zero.
It is per process: a lease's material lives on the member that materialised
it, so in a cluster each member reports its own, and the sum is the cluster's.

Page on `cloop_secret_unseal_failures_total`: any non-zero rate means the hub
can no longer read its own secrets. `reason` says what went wrong:

| `reason` | Meaning |
| --- | --- |
| `key_unknown` | ciphertext names a key-encryption key the hub has never seen |
| `key_retired` | it names a KEK that has been retired |
| `key_unavailable` | the KEK is known but can't be opened, usually because of a wrong or missing passphrase, or a KMS that refused to unwrap it |
| `kms_unavailable` | the KEK is held by a key-management service that can't be reached right now. The key itself may be fine |
| `seal_failed` | authenticated decryption failed: the ciphertext or its associated data has been altered |

None of these fixes itself. See the [runbook](runbook.md) for recovery.

`cloop_secret_kek_rotation_active` is 1 while a rotation is running. If it
stays at 1 across scrapes, the rotation has stalled with records still wrapped
under the old key:

```promql
min_over_time(cloop_secret_kek_rotation_active[30m]) == 1
```

`cloop_secret_kek_rotation_records` reports progress by `phase`: `total`,
`rewrapped`, `skipped`, `failed`. Both rotation gauges read the history that
`cloop hub key rotate` writes to the control-plane database, so they also
follow a rotation run from the command line. They are exported by the
[leader only](#hub-clusters-which-member-exports-what). A hub that has never
rotated reports `cloop_secret_kek_rotation_active 0` and no progress. A
rotation whose process was killed stays at 1 until the next one starts, which
is the stalled state the alert above catches.

### The key-management service

A hub whose sealing keys are held by an external KMS (`secrets.kms`) records
every call it makes to the KMS:

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_kms_requests_total` | counter | `backend`, `operation`, `result` |
| `cloop_kms_request_duration_seconds` | histogram | `backend`, `operation` |

`backend` is `kmsv2` (a Kubernetes KMS v2 plugin) or `transit` (Vault or
OpenBao). `operation` is `status`, `encrypt`, `decrypt` or `login` (Vault's
Kubernetes auth method). `result` is `ok`, `unavailable` (the KMS could not be
reached, or says it is not serving, such as a sealed Vault or an unhealthy
plugin), `timeout`, `denied` (the KMS refused the hub's identity), `invalid`
(it refused the request, for example for a ciphertext it doesn't hold or one
from another key) or `error`. Both are per process: each member counts the
calls it made, and the sum is the cluster's.

Every member polls its KMS's status once a minute, or every ten seconds while
it is unhealthy, so these metrics change even on a hub whose keys are all in
memory and which otherwise asks its KMS nothing. A KMS that stops answering
doesn't stop a running hub, because the keys it already opened keep working.
But no member started after that point can open the store, and a key minted in
the meantime can only be opened on the member that minted it. Alert on it
before that matters:

```promql
# The KMS is failing: any non-ok status poll over five minutes.
sum by (backend, result) (increase(cloop_kms_requests_total{operation="status",result!="ok"}[5m])) > 0

# The KMS is slow: the 99th percentile of its calls over a second.
histogram_quantile(0.99, sum by (le, backend) (rate(cloop_kms_request_duration_seconds_bucket[10m]))) > 1
```

`denied` won't fix itself: the hub's identity has lost access to the KMS key,
which is what a revocation looks like from the hub's side.

## Sign-in, sessions and API tokens

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_oidc_login_total` | counter | `outcome` |
| `cloop_oidc_renewal_total` | counter | `outcome` |
| `cloop_oidc_discovery_failures_total` | counter | none |
| `cloop_oidc_idp_fetches_total` | counter | `document`, `client`, `outcome` |
| `cloop_sessions_created_total` | counter | none |
| `cloop_sessions_terminated_total` | counter | `reason` |
| `cloop_sessions_live` | gauge | none |
| `cloop_session_reauth_total` | counter | `outcome` |
| `cloop_apitoken_auth_total` | counter | `result` |
| `cloop_apitoken_auth_failures_total` | counter | `reason` |

Session metrics have no subject label. Who holds which session is recorded in
the audit trail, behind `audit.read`.

A session is counted as created when a sign-in completes, and as terminated by
the call whose delete removed it from the session store. So a session that two
requests both found expired, or a janitor pass racing a sign-out, ends once
here, as it does in the audit trail. `reason` on termination is one of:

| `reason` | Meaning |
| --- | --- |
| `idle_evicted` | it went unused past the idle timeout |
| `absolute_expired` | it reached the ceiling set at sign-in |
| `self_logout` | the user signed out of it, or ended all their other sessions |
| `admin_revoked` | an operator terminated it, from the sessions panel or an offboarding |
| `idp_revoked` | the identity provider refused to renew the grant because the user was disabled there or withdrew consent |
| `quota_evicted` | the identity's session quota ended its least recently used session to make room for a new sign-in |

`cloop hub session revoke` deletes sessions from its own process, outside any
hub's registry. Those terminations lower `cloop_sessions_live` but don't appear
in `cloop_sessions_terminated_total`. The audit trail records them.

`cloop_sessions_live` counts the sessions valid at scrape time: neither past
their ceiling nor idle past the timeout, according to the session store (which
writes a session's last-seen time at most once a minute). It reads the shared
database, so it is exported by the
[leader only](#hub-clusters-which-member-exports-what), and it is 0 on a hub
without sign-on.

`cloop_apitoken_auth_total` counts every verdict on a presented API token.
`reason` on a failure is `malformed`, `not_found`, `bad_secret`, `revoked`,
`expired`, `no_roles` or `store_error`. The first six are problems with the
token. `store_error` is the hub's problem: its token store could not be read,
so every scraper and CI job holding a token is being turned away. A request
that the failure lockout refuses before verifying anything isn't counted
either way. A display-glasses link that verifies but is then refused by the
rules for its kind (a path outside the glasses views, or an owner it no longer
names) counts as a success. The token was genuine; the refusal was a matter of
authorization, not authentication.

`outcome` on a sign-in is `success`, `discovery_failed`, `idp_error`,
`invalid_request`, `invalid_state`, `exchange_failed`, `token_invalid`,
`session_error` or `state_error`. Different outcomes point to different
owners: `discovery_failed` to this hub's issuer setting, `exchange_failed` to
the client registration at the provider, `idp_error` to the provider's own
decision about the user, and `invalid_state` in any volume to somebody
replaying callbacks. A redirect to the provider isn't counted until it comes
back. Otherwise the success ratio would depend on how many people opened the
sign-in page and left.

**Nobody can sign in.** This catches it without anyone having to try:

```promql
rate(cloop_oidc_discovery_failures_total[5m]) > 0
```

A hub whose issuer has *never* resolved also reports `/readyz` as not ready,
with `"check": "identity"`, so a Kubernetes rollout stops instead of replacing
a working hub with one nobody can sign in to. After discovery has succeeded
once, the check stays passing: existing sessions keep working through a later
provider outage, and removing the hub from its Service during one would turn a
sign-in outage into a total outage. Run `cloop hub doctor` to see which of the
two round trips failed and why.

`cloop_oidc_idp_fetches_total` counts the issuer metadata documents this hub
process fetched. `document` is `discovery` or `jwks`, `outcome` is `ok` or
`error`, and `client` says who asked. `signin` is the hub's own sign-in client.
It resolves the issuer at startup and keeps the document. It fetches the key
set again only for a token signed by a key it doesn't hold and, while it has no
usable resolution, when a Hub health report asks it to retry (at most every 15
minutes). `preflight` is a standalone resolution: `cloop hub doctor`, the
**Test** button in **Settings → Single sign-on**, and the **Settings → Hub
health** check of an issuer the running client isn't using (at most once every
15 minutes per member). Hub health gets the issuer the hub signs in with from
its sign-in client, without asking the provider. A steady `preflight` rate
while nobody presses **Test**, or a `signin` rate while nobody signs in, means
something is asking the provider on every request:

```promql
sum by (client) (rate(cloop_oidc_idp_fetches_total[1h])) * 3600 > 30
```

`cloop_oidc_renewal_total` counts silent renewals: the `prompt=none` round trip
that a signed-in dashboard makes from a hidden frame to refresh its claims when
the hub has no refresh token to do it with (see
[Silent renewal from the browser](../security/model.md#silent-renewal-from-the-browser)).
It is separate from `cloop_oidc_login_total` because it happens every few
minutes per open tab and would swamp the sign-in ratio. `outcome` is `ok`,
`interaction_required`, `no_session`, `not_enabled`, `idp_error`,
`discovery_failed`, `state_error`, `invalid_state`, `exchange_failed`,
`token_invalid`, `subject_mismatch` or `store_error`.

Watch the ratio of `interaction_required` to `ok`. When it climbs, users are
being asked to sign in again mid-session, most often because their browser
keeps the provider's cookies out of frames, so the provider can't see its own
session there. The fix is on the hub side: set `CLOOP_SECRET_KEY` and request
`offline_access`, so the hub refreshes the claims itself and the browser
doesn't have to.

```promql
rate(cloop_oidc_renewal_total{outcome="interaction_required"}[15m])
  / clamp_min(rate(cloop_oidc_renewal_total[15m]), 1e-9) > 0.2
```

A renewal that fails inside the browser (a provider that refuses to be framed,
a frame that never answers) never reaches the hub and isn't counted here. The
dashboard shows the user a sign-in banner instead.

`cloop_session_reauth_total` counts sudo mode checks
([Recent sign-in for privileged actions](../security/model.md#recent-sign-in-for-privileged-actions)).
A privileged action, such as creating a secret or a grant, minting a token or
attaching to a sandbox, requires an interactive sign-in no older than
`ui.oidc.sudo_max_age_minutes`. `outcome` is `stale-refused` when a privileged
request is refused because the session's last sign-in is older than that
(every refusal is counted, although the audit trail writes at most thirty
`session.reauth` rows a minute). It is `granted` for a "Confirm it's you"
sign-in that was accepted, and `refused` for one that wasn't: a different
account, a provider that didn't ask, or a provider error. A person sees the
dialog and signs in, so `stale-refused` is normally followed by `granted`.
Refusals with nothing after them mean the session is being used by somebody who
can't sign in as its owner, for example with a stolen cookie:

```promql
increase(cloop_session_reauth_total{outcome="stale-refused"}[30m]) > 5
  and increase(cloop_session_reauth_total{outcome="granted"}[30m]) == 0
```

`session.reauth` rows in the audit trail say which session, from where, and
which request.

**Credential stuffing.** A spike in `bad_secret` means an existing token ID is
being tried with wrong secrets:

```promql
rate(cloop_apitoken_auth_failures_total{reason="bad_secret"}[5m]) > 1
```

## Requests from other origins

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_cross_origin_refusals_total` | counter | `reason` |

Counts requests the hub refused because a page on another origin sent them
(see [the threat model](../security/threat-model.md)). `reason` is one of:

| `reason` | Meaning |
| --- | --- |
| `cross_site` | the browser sent `Sec-Fetch-Site: cross-site` on a state-changing request |
| `same_site` | `Sec-Fetch-Site: same-site`: another port on the hub's host, or a sibling subdomain |
| `unknown_fetch_site` | a `Sec-Fetch-Site` value the hub doesn't recognise, refused without guessing |
| `foreign_origin` | no `Sec-Fetch-Site`, and an `Origin` that is none of the hub's own; also every refused WebSocket handshake |
| `media_type` | a state-changing request whose body is form data or `text/plain`, which is what a form on another site can send |
| `unknown_host` | a hub without sign-in was addressed by a host name it doesn't answer to, which is what DNS rebinding looks like |

The origin and host are recorded in the audit trail
([`request.origin_refused`](../reference/audit-events.md#request),
[`request.host_refused`](../reference/audit-events.md#request)), not as labels
here, because the sender chooses both. A burst of `foreign_origin` or
`media_type` right after a proxy change usually means the proxy no longer
passes the hub its own origin; see
[`ui.trusted_proxies`](../reference/configuration.md#tls).

```promql
sum by (reason) (rate(cloop_cross_origin_refusals_total[5m])) > 0
```

## What the page's policy blocked

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_csp_violations_total` | counter | `directive`, `document` |

Counts the Content-Security-Policy violations that browsers report to the
hub's `POST /api/csp-report` (see
[the configuration reference](../reference/configuration.md#content-security-policy-and-violation-reports)).
The hub's policy only lets its own script files run, so on a healthy hub this
stays at zero. `directive` is the effective directive: `script-src-attr`,
`script-src-elem`, `script-src`, `style-src-attr`, `style-src-elem`,
`style-src`, `img-src`, `connect-src`, `frame-src`, `frame-ancestors`,
`base-uri`, `form-action`, `object-src`, `default-src`, `worker-src`,
`font-src`, `media-src`, `manifest-src`, or `other`. `document` is the hub
document that reported it: `dashboard`, `glasses`, `sign-in` (the `/auth/`
documents) or `other`. A report contains whatever its sender wrote, so any
value outside those sets is counted as `other`. The blocked URL and the source
file are in the warn-level `csp_violation` log line and, with telemetry on, in
a `csp` event in the trail, never in the metric. The endpoint takes no
credential, so the counter counts whatever senders claim. Before acting on a
spike, read the `client_ip` and `actor` in those log lines: a report from a
signed-in browser names its user.

| What it looks like | What it usually is |
| --- | --- |
| `script-src-attr` on `dashboard` | a control whose inline handler was missed in a conversion (a button that does nothing), or a handler attribute in injected markup, which the policy stopped |
| `script-src-elem` | an inline `<script>` or one from another origin: a page change that did not load its script as an asset, or an injection |
| `script-src` with `blocked` `eval` | code that compiles strings, which the policy has never allowed |
| `frame-src` | a renewal frame sent somewhere the policy doesn't list, usually because an identity provider's authorization endpoint moved to another origin |

Each of these is a defect or an attack, so alert on any non-zero rate.

```promql
sum by (directive, document) (increase(cloop_csp_violations_total[15m])) > 0
```

## Write-back

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_writeback_bundles_total` | counter | `result` |
| `cloop_writeback_rejections_total` | counter | `reason` |

`result` is `accepted`, `rejected` or `unavailable`. `rejected` means the hub
refused what a sandbox returned; `unavailable` means the hub couldn't find out
whether to accept it. They need different responses: the first points to a
misbehaving or compromised sandbox, the second to broken infrastructure.

`reason` is an `executor.WriteBackReason*` code. The full refusal message is in
the audit trail instead, because it includes branch names and commit SHAs.

### Returned work held in memory

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_writeback_pinned_bytes` | gauge | none |
| `cloop_writeback_pinned_bytes_max` | gauge | none |
| `cloop_writeback_frame_refusals_total` | counter | `reason` |

A remote executor returns two things that the hub keeps in memory until it
collects them: a write-back bundle, assembled from result chunks, and a seeded
run's project-state document. `cloop_writeback_pinned_bytes` is everything this
hub process holds, limited by
[`executors.remote.max_pinned_writeback_total_bytes`](../reference/configuration.md#returned-work-held-in-memory).
`cloop_writeback_pinned_bytes_max` is the most that any single executor holds,
against its own `max_pinned_writeback_bytes` budget. Both count what the budget
counts: the bytes held, plus 64 for each bundle chunk holding them, so a bundle
in 256 KiB chunks reads a fortieth of a percent above its size. Neither has an
executor label (a fleet of devices is the kind of unbounded set the catalog's
rule exists for), so the max is what tells you that one device is close to its
budget. Both are per process: in a hub cluster, each member holds what reached
it.

Collected work is released immediately, so on a healthy hub both stay near zero
between runs and rise only while a bundle is in transit. A level that stays
high means work nobody is collecting (it is released 15 minutes after its run
ended), or a device holding transfers open:

```promql
max(cloop_writeback_pinned_bytes_max) > 0.8 * 268435456   # 80% of the default budget
```

`cloop_writeback_frame_refusals_total` counts result frames refused before
their bytes were stored:

| `reason` | Meaning |
| --- | --- |
| `late` | a chunk, result or project-state document for a handle that had already reported its final status, or a chunk or result after the write-back closed with its result frame |
| `not_requested` | a chunk for a handle whose spec asked for no bundle, a result for one that asked for no write-back, or a project-state document for a run that was not seeded |
| `over_cap` | a chunk that took the bundle past the cap the handle's spec asked for |
| `executor_budget` | holding it would take the executor past `max_pinned_writeback_bytes` |
| `process_budget` | holding it would take the hub process past `max_pinned_writeback_total_bytes` |

A correctly working agent sends chunks, then the result, then the final status,
and nothing after that. So any `late` or `not_requested` refusal means a device
is broken or compromised. Alert on it, and find the executor in the hub's log.
The two budget reasons are capacity problems: the refused run's journal names
the limit and how much was held.

```promql
sum by (reason) (rate(cloop_writeback_frame_refusals_total{reason=~"late|not_requested|over_cap"}[5m])) > 0
```

## Merge queue

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_mergequeue_depth` | gauge | none |
| `cloop_mergequeue_merges_total` | counter | `outcome` |

`outcome` is `clean`, `auto_resolved`, `unresolved` or `error`.

The queue merges one change at a time, so a depth that stays high means
integration is falling behind task completion:

```promql
min_over_time(cloop_mergequeue_depth[15m]) > 5
```

A rising `unresolved` rate means the AI conflict resolver is handing conflicts
back to a person.

## Git interception proxy

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_gitproxy_pushes_total` | counter | `result` |
| `cloop_gitproxy_push_denials_total` | counter | `reason` |
| `cloop_gitproxy_anonymous_requests_total` | counter | none |
| `cloop_gitproxy_push_scans_total` | counter | `result` |
| `cloop_gitproxy_push_scanned_bytes_total` | counter | none |
| `cloop_gitproxy_push_scan_seconds` | histogram | none |

Sandboxes push through this proxy, so its denial counter is a security signal
as well as an operational one. `reason` is `ref_not_allowed`, `delete_denied`,
`create_denied`, `update_denied`, `no_write`, `too_many_commands` or
`push_cert`, or, from the push scan, `secret_in_push` (the push carries a
credential its run was given), `scan_limit` or `unreadable_pack`. Look into
every `secret_in_push`: a run tried to publish a credential. `no_write` is
defined, but no code path produces it today. A session that may not push is
refused before any command is parsed (at the receive-pack advertisement, or at
the push itself when a client skips discovery), so that refusal is a
`gitproxy.rejected` audit row and appears in neither counter. The counters only
see pushes. Fetches, sessions, and requests for a repository outside a
session's scope are recorded only in the audit trail.

`cloop_gitproxy_anonymous_requests_total` counts requests that presented no
credential at all. They aren't written to the audit trail. Nearly all of them
are git's own authentication challenge (a bare request, answered with 401,
before git retries with the lease's session credential), and the rest are
anything else that reaches the proxy's port. This counter closely follows the
proxy's own traffic; a rate far above it means something other than git is
making the requests.

**A sandbox probing the allowlist**

```promql
rate(cloop_gitproxy_push_denials_total{reason="ref_not_allowed"}[5m]) > 0.1
```

**The push scan.** On its way to the forge, every push the policy allows is
inflated and scanned for the credentials its run was given
([how it works](../architecture/git-proxy.md#the-push-scan)).
`cloop_gitproxy_push_scans_total` counts these scans by `result`: `clean`,
`secret` (refused for containing a credential), `limit` (refused at an
`executors.git_proxy.push_scan_*` limit), `unreadable` (a pack the proxy could
not read, refused), `incomplete` (the sandbox or the forge went away during
the scan) and `unscanned` (`push_scan: off`). The scanned-bytes counter and the
duration histogram (time spent inflating and matching, not waiting on either
side) show what the scan costs the hub. A push whose scan approaches
`executors.git_proxy.push_scan_seconds` is about to be refused for taking too
long.

```promql
increase(cloop_gitproxy_push_denials_total{reason="secret_in_push"}[1h]) > 0
histogram_quantile(0.99, sum by (le) (rate(cloop_gitproxy_push_scan_seconds_bucket[1h])))
```

## Kubernetes access monitor

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_kubeguard_requests_total` | counter | `result` |
| `cloop_kubeguard_denials_total` | counter | `reason` |

These work like the git proxy's metrics above. A sandbox's `kubectl` goes
through this monitor, so the denial counter shows whether anything is testing
that boundary. `result` is `allowed` or `denied`. `reason` is
`verb_not_allowed`, `namespace_not_allowed`, `cluster_scope`,
`resource_not_allowed`, `dangerous_subresource`, `non_resource_path`,
`protocol_upgrade`, `body_too_large` or `unauthenticated`, or, for a write
that would mint a credential outside the monitor,
`service_account_token_secret`, `workload_service_account`, `host_access`,
`rbac_binding`, `rbac_role`, `certificate_signing_request` or `unreadable_body`.
A steady stream of `verb_not_allowed` means a workload expects write access it
wasn't granted. `dangerous_subresource` is an attempt to open a shell inside a
pod, and any of the credential reasons is a workload trying to get a credential
of its own.

A failure on the proxy side (an unreachable cluster, an unusable credential)
is counted as neither allowed nor denied, so it doesn't distort the denial rate
during the outages an operator gets paged for.

**A workload expecting write access it was not granted**

```promql
rate(cloop_kubeguard_denials_total{reason="verb_not_allowed"}[5m]) > 0.1
```

**An attempt to get a shell in a pod.** The monitor refuses `exec`, `attach`,
`portforward`, `proxy` and `ephemeralcontainers` for every verb, so this should
stay at zero:

```promql
rate(cloop_kubeguard_denials_total{reason="dangerous_subresource"}[5m]) > 0
```

**A workload minting a credential of its own:** a token Secret, a workload
running as another ServiceAccount or on the node, RBAC, or a certificate. This
should also stay at zero:

```promql
sum(rate(cloop_kubeguard_denials_total{reason=~"service_account_token_secret|workload_service_account|host_access|rbac_binding|rbac_role|certificate_signing_request"}[5m])) > 0
```

See [the Kubernetes access monitor](../architecture/kubernetes-access.md) for
what each reason means.

## The hub's certificate authority

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_hub_ca_not_after_timestamp_seconds` | gauge | `slot` |
| `cloop_hub_ca_rotation_phase` | gauge | `phase` |
| `cloop_hub_ca_rotation_step_age_seconds` | gauge | none |
| `cloop_hub_ca_runs_blocking` | gauge | none |
| `cloop_hub_ca_members_behind` | gauge | none |
| `cloop_hub_ca_leaves_issued_total` | counter | `monitor`, `reason` |
| `cloop_hub_ca_trust_adoptions_total` | counter | none |
| `cloop_hub_ca_sessions_ended_total` | counter | `proxy` |

These cover the CA that issues the git proxy's and the Kubernetes monitor's
certificates under `tls: auto`, and [rotating](runbook.md#rotating-the-hub-ca)
that CA. The five gauges read the shared database, so only the cluster leader
exports them. The counters are per member.

`cloop_hub_ca_not_after_timestamp_seconds` is when each CA expires, by `slot`:
`active` (the one that issues leaf certificates), `next` (staged) and
`previous` (replaced, not yet retired). Replacing the active CA is a staged
rotation that waits for runs, so alert months ahead, not days:

```promql
cloop_hub_ca_not_after_timestamp_seconds{slot="active"} - time() < 90 * 86400
```

`cloop_hub_ca_rotation_phase` is 1 for the current phase (`none` if no CA has
been minted, `steady`, `staged` or `activated`) and 0 for the others.
`cloop_hub_ca_rotation_step_age_seconds` is how long ago the current rotation
took its last step. A stage shouldn't last much longer than the longest
`session_minutes` a monitor grants, and a previous CA shouldn't outlast its
activation by much either:

```promql
cloop_hub_ca_rotation_phase{phase=~"staged|activated"} == 1
  and on() cloop_hub_ca_rotation_step_age_seconds > 6 * 3600
```

`cloop_hub_ca_runs_blocking` counts the running runs that the next step would
break. While staged, these are the runs not given the staged CA, which an
activation waits for. Once activated, they are the runs given only the
previous CA. `cloop_hub_ca_members_behind` counts live members that haven't
adopted the current step, or whose build predates CA rotation. Activation is
refused while any such member is live.

`cloop_hub_ca_leaves_issued_total` counts the monitor certificates this member
issued, by `monitor` (`git_proxy`, `kube_guard`) and `reason`: `first`,
`renewal` (by the leader, two days before expiry), `names` (a member needed a
name the stored certificate lacked), `activation` (a rotation made another CA
active) and `unreadable`. About one renewal per monitor per day is normal. A
burst of `names` means two members are taking turns.
`cloop_hub_ca_trust_adoptions_total` counts each time this member started
giving sandboxes a different set of CAs, once per rotation step it saw.
`cloop_hub_ca_sessions_ended_total` counts the proxy sessions this member ended
because an emergency rotation (`--now`) named their runs, by `proxy`
(`git_proxy`, `kube_guard`, `model_relay`).

## Egress broker

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_egress_requests_total` | counter | `result` |
| `cloop_egress_denials_total` | counter | `reason` |
| `cloop_egress_bytes_total` | counter | `direction` |
| `cloop_egress_sessions_live` | gauge | none |

The broker records these itself, from the same typed error that each audit row
is built from, so a verdict can't appear in one and not the other. All four are
per process: a session lives in the broker that issued it, and so do its
verdicts and its bytes. On a hub they come from the proxy that `cloop ui` hosts
when [`executors.egress`](../reference/configuration.md#scoped-network-egress)
is enabled, and they follow the runs it issues sessions to. In a hub cluster,
every member hosts its own proxy and reports its own numbers, and the cluster's
value is the sum. `cloop egress test` runs its own proxy in its own process for
the length of one test, and its samples stay in that process. A hub with the
section disabled exports the families with no samples.

`cloop_egress_requests_total` counts the requests through the proxy that
reached a policy verdict: a CONNECT tunnel opened or refused, or a plain-HTTP
exchange forwarded or refused. A request that failed for lack of DNS or a
route, or was malformed, is neither allowed nor denied, so such failures don't
move the denial rate during an outage. A request with no valid credential is
refused with 407 and not counted anywhere (as in the audit trail, counting
starts at an authenticated session). A request on a session that is spent,
expired or past its quota does get a verdict and is counted.

`cloop_egress_denials_total` counts every refusal the broker makes, which
covers more than denied requests. `no_grant`, `revoked` and `expired` (for an
expired grant) refuse a *session* when one is requested, before any request
exists. `quota_exhausted` and `expired` also cut off a transfer the broker had
allowed, when a budget runs out or a session's TTL ends inside an open tunnel.
That request already has its `allowed` sample, so only the denial is added.

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

`direction` on `cloop_egress_bytes_total` is `up` (from the sandbox) or `down`
(to it). It includes the bytes of a transfer that its quota then cut off, since
they did cross the control plane. `cloop_egress_sessions_live` counts the
sessions a process has issued and not yet closed. On a hub that is roughly one
per run holding a grant, because a session is renewed for as long as its run
lives and closed when the run ends. An expired session is closed within the
proxy's reap interval.

Alert on `destination_blocked`: a sustained rate means a sandbox is trying to
reach the hub's own network.

```promql
rate(cloop_egress_denials_total{reason="destination_blocked"}[5m]) > 0
```

## Sandbox firewall refusals

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_firewall_denials_total` | counter | `executor_kind`, `rule` |
| `cloop_firewall_denial_reports_dropped_total` | counter | `reason` |

A sandbox's IP firewall refuses a blocked connection and logs it, rate-limited,
to an NFLOG group. The hub reads that log for its own container executor, and
each edge device's agent reads its own log and reports it per run over its
session (protocol v24). Both families are recorded when the hub records each
batch on its run, so they are per process: a device's refusals are counted by
the member holding its session.

`rule` on `cloop_firewall_denials_total` is the deny path that refused the
packet: `default` (no allow rule matched), `deny` (a deny list), `meta` (a
cloud metadata service), `block` (the rest of the hard-block set: private,
loopback, link-local, CGNAT, multicast), `xlat` (an IPv6 translation prefix),
or `unitemised` for refusals that a run's capped aggregate counted without
listing them individually. The log is limited to ten lines a second per deny
path, so a flood shows up as at least that rate, not as every packet.
Kubernetes executors report nothing, because a NetworkPolicy has no portable
log of what it refused.

`cloop_firewall_denial_reports_dropped_total` counts the reports the hub did
not record, by `reason`:

| `reason` | Meaning |
| --- | --- |
| `late` | a device reported after its workload's final status |
| `no_sink` | the process received a report with no hub in it to record it |
| `rate` | a device sent a run's reports faster than the per-run limit |
| `malformed` | the report failed validation (bounds, addresses, rules) |
| `unknown_run` | no run in this process owns the handle |
| `queue_full` | the recorder was behind and the report was discarded |

A run trying to reach something the firewall denies shows up here first:

```promql
sum by (rule) (rate(cloop_firewall_denials_total[5m])) > 0
```

## Model relay

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_model_relay_requests_total` | counter | `outcome` |
| `cloop_model_relay_refusals_total` | counter | `reason` |
| `cloop_model_relay_tokens_total` | counter | `kind` |
| `cloop_model_relay_cost_usd_total` | counter | none |
| `cloop_model_relay_sessions_live` | gauge | none |
| `cloop_model_relay_usage_gap_tokens_total` | counter | `direction` |

With [`executors.model_relay`](../reference/configuration.md#the-model-relay-for-sandboxed-runs)
on, a run on an isolating executor presents a relay session instead of its
Claude credential, and the hub uses the credential upstream. Every family is
per process: a session is served by the member holding its run's lease, which
records its calls. In a hub cluster, the sum is the hub's total. A hub with the
relay off exports the families with no samples.

`cloop_model_relay_requests_total` counts every call that reached the relay.

| `outcome` | Meaning |
| --- | --- |
| `allowed` | relayed to the API with the run's credential; its usage is in the families below |
| `refused` | refused by policy or budget, without reaching the API. `cloop_model_relay_refusals_total` says which |
| `ended` | presented the token of a session that has ended (its run is over, or its grant or lease was revoked), and got a 403 saying why |
| `rejected` | carried no usable token: a stray request, or a harness probing the base URL |

| `reason` | Meaning |
| --- | --- |
| `budget_exhausted` | the identity paying for the run has spent its `daily_token_budget` or `daily_cost_usd` |
| `model_not_allowed` | the model is outside the hub's allowlist or the project's narrower one |
| `path_not_allowed`, `method_not_allowed` | the call is not to the Messages, token-counting or models API |
| `body_too_large`, `body_malformed` | the request could not be read or exceeded the body limit |

`cloop_model_relay_tokens_total` is the token usage the API reported for
relayed calls, by `kind`: `input` (uncached), `output`, `cache_read` and
`cache_write`. `cloop_model_relay_cost_usd_total` is the same usage priced in
dollars, with cache tokens at their own rates. These are what each run's payer
is charged. The identity is never a label; what each identity spent today is in
`cloop_quota_usage`. `cloop_model_relay_sessions_live` counts the sessions a
process serves, about one per relayed run in progress.

`cloop_model_relay_usage_gap_tokens_total` is the difference, at the end of
each relayed run, between the tokens the run wrote to its own ledger and the
tokens the relay counted: `unreported` when the relay counted more,
`overreported` when it counted less. The `claudecode` provider writes no token
counts at all, so all of its relayed tokens are `unreported`. That is expected
and not a problem. For the `anthropic` provider, which does report usage, watch
the ratio.

```promql
sum(rate(cloop_model_relay_refusals_total{reason="budget_exhausted"}[15m])) > 0
sum by (kind) (increase(cloop_model_relay_tokens_total[1d]))
```

## Sessions restored with an adopted run

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_proxy_session_restores_total` | counter | `kind`, `outcome` |

When a hub process adopts a device run that another process stopped serving
(after a restart in the same directory, or when a cluster member died), it
restores what the run's lease provides: the run's git proxy, Kubernetes monitor
and egress sessions, under the IDs and tokens the workload already holds, and
the GitHub App token slots that keep its tokens valid past GitHub's one-hour
limit. Each restore it attempts is counted here, by the process that adopted
the run. A CI relay session whose holder stopped is restored by the process
that receives the job's next call, and counted there under `kind` `ci` (for
these, `refused` means the session's rule was deleted, disabled or no longer
admits the pipeline). A run's model relay session comes back with its lease,
under `kind` `model`. `kind` is `git`, `kube`, `egress`, `app_token`, `ci` or
`model`.

| `outcome` | Meaning |
| --- | --- |
| `restored` | served again by this process; the workload noticed nothing |
| `refused` | won't be restored: its grant was revoked or expired while no process held it, its recorded scope is wider than the grant or this hub's proxy policy now allows, its upstream is not the forge this hub's git proxy fronts, or this process runs no proxy to serve it. It is closed with the reason |
| `expired` | lapsed while no process held it |
| `lost` | another process restored it first, or took over it or its lease before a retry; or the lease was handed over or released while it waited |
| `failed` | its upstream credential could not be re-derived, for a reason that may be temporary (the store busy, GitHub unreachable). This process keeps it and retries on every lease keepalive tick (egress: after two seconds, doubling up to a minute, together with the run's other [undecided takeovers](#credentials-taken-over-with-an-adopted-run)), and immediately when the workload's next request presents it |

After a restart, look at `refused` and `expired`. Each one is a workload that
gets a 401 on its next git, kubectl or proxied request, and the session's
`*.session_closed` or `egress.close` row says why. A rising `failed` count that
doesn't turn into `restored` means GitHub is out of reach from the hub.

```promql
sum by (kind, outcome) (increase(cloop_proxy_session_restores_total[1h]))
```

## Credentials taken over with an adopted run

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_lease_takeovers_total` | counter | `kind`, `outcome` |

This covers the credentials themselves, one level above the sessions in the
previous section. A hub process adopting a run tries to take over each
credential named in the run's owner row, and counts every attempt here. `kind`
is `run` (a secret lease), `workspace` (the lease that a device workspace's
pinned git session depends on) or `egress` (an egress proxy session).

| `outcome` | Meaning |
| --- | --- |
| `taken_over` | now held by this process; what depends on it is restored |
| `moved` | another process holds it: the one that adopted the run first or, for an egress session, a live member that still serves it (this process takes it over if that member stops) |
| `not_found` | released, or never recorded |
| `revoked` | revoked while no process held it, and taken back from the workload |
| `refused` | lapsed, or its grants no longer authorise it; taken back |
| `retrying` | no decision was possible (the secret store briefly unreadable, the database locked, a KMS down). It is tried again after two seconds, then with the wait doubling up to a minute, until it is decided or its recorded expiry passes |
| `failed` | still undecided when it lapsed or when its run ended. Recorded in the run's event history (`lease_takeover`). The run continued without it, and its git pushes and kubectl calls through the hub were refused |

A series of `retrying` that ends in `taken_over` was a store that came back in
time. Alert on `failed`: each one is a run that lost a credential because of a
fault the hub couldn't get past. While a takeover is `retrying`,
`cloop hub doctor` and **Settings → Hub health** show a `runs.lease_takeovers`
warning naming the run.

```promql
sum by (kind) (increase(cloop_lease_takeovers_total{outcome="failed"}[1h])) > 0
```

## Quotas and admission control

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_quota_enforcement_enabled` | gauge | none |
| `cloop_quota_limit` | gauge | `identity`, `resource` |
| `cloop_quota_usage` | gauge | `identity`, `resource` |
| `cloop_quota_denials_total` | counter | `resource` |
| `cloop_quota_identities` | gauge | none |
| `cloop_projects_registered` | gauge | none |

`resource` is a `quota.Resource`: `max_projects`, `max_executors`,
`max_sessions`, `max_concurrent_tasks` and the daily budgets.

These names and label schemas are older than the registry and are kept
unchanged, because existing scrape configs and recording rules use them. The
gauges describe the policy, the usage that the members' enforcers share through
the database, and the project registry, so a cluster exports them from its
[leader only](#hub-clusters-which-member-exports-what).
`cloop_quota_denials_total` counts each member's own refusals and is exported
by every member.

**Identities near their limit.** This alert warns a tenant before admission
starts failing:

```promql
cloop_quota_usage / cloop_quota_limit > 0.9
```

**Admission is refusing work**

```promql
sum by (resource) (rate(cloop_quota_denials_total[5m])) > 0
```

## Disk

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_hub_disk_free_bytes` | gauge | `volume` |

The free space each hub process can still use on the volumes it writes to: the
one holding its control-plane `.cloop` (where `state.db` lives) and those of
the projects registered with it, one sample per filesystem. `volume` is the
mount point. Free means writable by this process: a hub running as root counts
the blocks the filesystem reserves for root, and an unprivileged one doesn't.

Runs pause before their next task or evolve round while a volume they write to
is below `orchestrator.min_free_disk_mb` (1 GiB by default), and resume by
themselves once it is back above the floor plus a tenth. The
`storage.free_space` finding of `cloop hub doctor` warns below twice the floor
and fails below it. Alert before the floor is reached:

```promql
min by (volume) (cloop_hub_disk_free_bytes) < 2 * 1073741824
```

Every member exports it for its own disk, so members sharing a volume report
the same reading. Aggregate with `min()` by volume, not `sum()`. The set of
series is reset on every scrape and capped at 32 volumes.

## Hub health

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_hub_health_reports_total` | counter | `trigger` |

Counts the **Settings → Hub health** reports each hub member makes about
itself. `trigger` is `schedule` (the member's interval, `ui.hub_health_interval`,
five minutes by default, came round), `config` (one of its configuration files
changed), `event` (an executor enrolled, was lost or was reconfigured, a CA
rotation took a step, or a sealing key changed; a burst of events produces one
report, at most one a minute), `rerun` (an administrator pressed **Run the
checks again**) or `request` (a read found no report it could serve, as with
the first one after startup).

A member pushes each report's summary to the dashboards allowed to read it, and
a page asks for a report only when its socket opens, so the rate doesn't grow
with the number of administrators' open tabs. Each member counts its own
reports, so read it per member:

```promql
sum by (instance) (rate(cloop_hub_health_reports_total[1h])) * 3600 > 30
```

fires on a member making more than 30 an hour. With the default interval, that
means something is asking for reports on readers' behalf.

## Control-plane database

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_statedb_wal_bytes` | gauge | none |

The size of the hub database's write-ahead log, `.cloop/state.db-wal`, read at
scrape time. Every write goes through the log before a checkpoint copies it
into `state.db`. SQLite never shrinks the file by itself, so a burst of writes
(a bulk delete by row retention or an audit prune, or a VACUUM, which writes
the whole database through the log) would leave it at that size for as long as
the hub ran. To prevent that, every read-write connection trims it to 64 MiB
when it starts the log over, and the leader's janitor truncates it after each
retention pass and within a minute of finding it larger.

Normally the log is a few megabytes, with spikes during large writes that come
back down within minutes. A log that stays over 64 MiB is being held by
something: a connection still reading from it (the leader's checkpoint reports
"busy" and retries every minute), or writers that all predate the limit. The
[runbook](runbook.md#the-write-ahead-log) explains how to tell which.

```promql
cloop_statedb_wal_bytes > 64 * 1048576
```

with a `for:` of half an hour, which no single burst lasts. It is a gauge of
the shared database's directory, so only the cluster leader exports it. A hub
with no database yet exports nothing.

## Audit trail

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_audit_append_failures_total` | counter | `chain`, `reason` |
| `cloop_audit_gap_events_total` | counter | `chain` |
| `cloop_audit_checkpoints_total` | counter | `outcome` |

A failed audit append leaves no trace in a hash chain: the next append links
to the last one that succeeded, and verification reports an intact chain over
a trail with holes in it. So the append path counts every failure itself,
whatever its caller does with the error. `cloop_audit_append_failures_total` is
the number of events lost, by the role of the database handle (`control-plane`,
`project` or `unclassified`) and the failure class (`locked`, `readonly`,
`full`, `io`, `closed` or `other`). `cloop_audit_gap_events_total` is how many
of those have since been recorded in their chain as part of an `audit.gap`
row. That happens with the next successful append on that chain, at a flush
every 30 seconds, or at shutdown. The difference is what a process still owes
the trail:

```promql
sum(increase(cloop_audit_append_failures_total[10m])) > 0
sum(cloop_audit_append_failures_total) - sum(cloop_audit_gap_events_total) > 0
```

The first pages on any loss. The second, with a `for:` of ten minutes, tells
you the database still isn't accepting writes. Losses that a hub takes over
from a process that exited still owing them are counted in both (in the first
when it takes them over, in the second when it records them), so the
difference still shows what is owed. Both are per member and sum across a
cluster. A project's losses are counted by the `cloop run` process that writes
its chain, which a scrape of the hub doesn't see; the gap row in the project's
chain is the record of those. `reason="full"` usually comes with
[`cloop_hub_disk_free_bytes`](#disk) near zero.

`cloop_audit_checkpoints_total` counts the head checkpoints that the cluster
leader writes outside the database, one per chain per
`audit.checkpoints.interval`: `outcome="signed"` when signed with the key
derived from `CLOOP_SECRET_KEY`, `unsigned` on a hub without that key, and
`failed` when the configured file could not be written.

```promql
increase(cloop_audit_checkpoints_total{outcome="failed"}[15m]) > 0
sum(increase(cloop_audit_checkpoints_total[30m])) == 0
```

The second catches checkpoints stopping altogether: no leader, or a window
marker that won't advance. See the
[runbook](runbook.md#audit-chain-verification).

### Forwarding the trail off the box

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_audit_forward_rows_total` | counter | `sink`, `outcome` |
| `cloop_audit_forward_lag_seconds` | gauge | `sink` |
| `cloop_audit_forward_backlog_rows` | gauge | `sink` |

The cluster leader sends every chain's rows to the sinks in `audit.forward`,
and moves each sink's cursor forward only after the sink acknowledges them
(see the [runbook](runbook.md#forwarding-the-trail-off-the-box)).
`cloop_audit_forward_rows_total` counts what it handled, per sink:

| `outcome` | Meaning |
| --- | --- |
| `delivered` | the sink acknowledged the rows |
| `truncated` | acknowledged, with the payload left out to fit a syslog sink's `max_message_bytes`. The record says so and includes the payload's length and SHA-256 |
| `failed` | a send that failed. The rows stay in the database and are sent again, so one row can be counted here many times |
| `lost` | rows the sink can no longer receive: pruned before it acknowledged them (a prune forced past its cursor, leaving the rows only in the prune's archive), or missing from the chain. An `audit.forward.discontinuity` row says which |

`cloop_audit_forward_lag_seconds` is the age of the oldest row the sink hasn't
acknowledged, across all chains, or 0 when it is caught up.
`cloop_audit_forward_backlog_rows` is how many rows are waiting. The leader
reads both from its forwarder and is the only member that exports them, so a
follower's scrape has neither, and they are briefly absent during a leadership
hand-over.

```promql
max by (sink) (cloop_audit_forward_lag_seconds) > 900
increase(cloop_audit_forward_rows_total{outcome="lost"}[1h]) > 0
```

The first is the doctor's `audit.forward.max_lag` check as an alert. It covers
a sink that has stopped accepting rows as well as one that is falling behind,
because the oldest waiting row keeps getting older. The second fires on any row
a sink will now never receive. Don't page on `failed` alone: a collector
restarting fails a batch or two, and the rows are sent again.

## Approval notifications

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_approval_notifications_total` | counter | `sink`, `event`, `outcome` |

The cluster leader posts to the webhooks in `notifications.webhooks` when a
grant request is filed, 12 hours before it lapses, when it is approved, denied,
withdrawn or lapses, and when an API token starts waiting for an administrator
(see [the configuration reference](../reference/configuration.md#approval-notifications-notifications)).
`sink` is the webhook's name. `event` is one of `request.filed`,
`request.reminder`, `request.approved`, `request.denied`, `request.withdrawn`,
`request.lapsed`, `token.waiting`, `requirement.regression` (a requirement that
passed before and that the requirements gate, or any check, found broken), or
`test` for a message sent from Settings.

| `outcome` | Meaning |
| --- | --- |
| `delivered` | the webhook answered 2xx |
| `failed` | one send that failed; the notice is retried after a backoff, so one notice can count here several times |
| `dropped` | given up on after 8 failed sends, a refusal that retrying can't change (a 4xx other than 408, 425 or 429, a redirect, an address the guard refuses), or because the notice is a day old |
| `superseded` | a filing or reminder not sent because the request was decided before it could go out, or a waiting notice for a token approved or revoked meanwhile |

Only the leader sends, so in a cluster the series come from whichever member
was leader at the time. `sum()` over members gives the cluster's total.

```promql
increase(cloop_approval_notifications_total{outcome="dropped"}[1h]) > 0
```

A dropped notice means an approver wasn't told. **Settings → Notifications**
shows each webhook's last error.

## Knowledge syncs

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_knowledge_sync_duration_seconds` | histogram | `kind`, `outcome` |
| `cloop_knowledge_documents_indexed_total` | counter | `kind`, `change` |
| `cloop_knowledge_sync_errors_total` | counter | `kind`, `reason` |
| `cloop_knowledge_index_documents` | gauge | `kind` |
| `cloop_knowledge_index_chunks` | gauge | `kind` |
| `cloop_knowledge_index_bytes` | gauge | `kind` |

The hub-cluster leader syncs every enabled knowledge source on the source's
interval (30 minutes, unless the source sets a value from 5 minutes to 24
hours). Any member runs a sync that a person asks for with
`cloop knowledge sync` or `POST /api/knowledge/sources/{id}/sync`. Each sync
holds the source's lease, so two syncs of a source never run at once, wherever
they were requested. `kind` is the connector: `confluence`, `jira`, or
`unknown` for a source of a kind this build has no connector for.

`cloop_knowledge_sync_duration_seconds` times every sync, by `outcome`: `ok`,
`error`, or `interrupted` (the process running it stopped, or stopped being
leader, and the next sync resumes from its cursor). Its `_count` is the number
of syncs.

`cloop_knowledge_documents_indexed_total` counts what syncs did with each
document they listed, by `change`: `created` and `updated` (chunked and
indexed), `unchanged` (listed again with the same content, not chunked again),
`deleted` (the source reported it deleted), `removed` (a full listing's sweep
or a reconciliation found it gone) and `rejected` (malformed, left out).

`cloop_knowledge_sync_errors_total` counts failed syncs by `reason`:

| `reason` | Meaning |
| --- | --- |
| `connector` | the remote answered an error, could not be reached, or sent what the sync refuses |
| `credential` | the source's secret could not be opened: it was deleted, or belongs to the wrong owner |
| `panic` | the connector, or the sync, panicked; that sync failed and no other |
| `lease` | the sync could not renew its source's lease, and stopped |
| `unavailable` | the hub has no connector of the source's kind, or no secret store |
| `storage` | the hub's database failed a read or a write |

A sync overtaken by a change to its source (reconfigured, renamed, its interval
changed) isn't a failure. It is recorded as `interrupted`, and the next sync,
within a minute, picks up the change.

The three index gauges describe the shared database, so only the leader
exports them. They are the documents the index holds (not counting the
tombstones of deleted documents), its chunks, and the bytes of document text
the chunks were made from.

```promql
increase(cloop_knowledge_sync_errors_total[1h]) > 0
histogram_quantile(0.95, sum by (le, kind) (rate(cloop_knowledge_sync_duration_seconds_bucket[1h])))
```

A source that keeps failing shows the reason on the source itself:
`cloop knowledge sources` prints each source's status and last error, with
credentials removed.

## Knowledge search and embeddings

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_knowledge_searches_total` | counter | `retrieval` |
| `cloop_knowledge_search_vectors_compared_total` | counter | none |
| `cloop_knowledge_search_vector_scan_seconds` | histogram | none |
| `cloop_knowledge_search_vectors_capped_total` | counter | none |
| `cloop_knowledge_embedding_requests_total` | counter | `purpose`, `outcome` |
| `cloop_knowledge_embedding_request_duration_seconds` | histogram | `purpose` |
| `cloop_knowledge_embedded_chunks_total` | counter | `kind`, `outcome` |
| `cloop_knowledge_index_vectors` | gauge | `kind` |

With [`knowledge.embeddings`](../reference/configuration.md#semantic-knowledge-search-knowledgeembeddings)
on, each chunk gets a vector from the embedding endpoint during its source's
sync, and a search combines a ranking by words with a ranking by meaning. Every
family except the gauge is per process.

`cloop_knowledge_searches_total` counts knowledge searches by `retrieval`:
`lexical` (embeddings are off), `hybrid` (both rankings, combined), and
`fallback` (embeddings are on, but the query could not be embedded, so the
search ranked by words alone). A share of `fallback` means the endpoint is
failing searches. Each such search is answered with a `warning` saying why.

`cloop_knowledge_search_vectors_compared_total` counts the vectors that hybrid
searches compared their query with (the current vectors of the searching
project's bound sources), and `cloop_knowledge_search_vector_scan_seconds`
times each comparison. That scan is what a hybrid search costs, and it grows
with the project's knowledge. Divided by the number of hybrid searches, the
counter gives the vectors one search compares.
`cloop_knowledge_search_vectors_capped_total` counts the searches that found
more than `max_candidates` and compared only that many.

`cloop_knowledge_embedding_requests_total` counts requests to the endpoint by
`purpose` (`document` for a sync's batch of chunks, `query` for a search's) and
`outcome`: `ok`; `error` (the request failed, timed out or got an error
answer); `rejected` (the endpoint answered with vectors the hub refuses: too
many, too few, the wrong length, or not numbers); or `skipped` (a query not
sent because the endpoint failed within the last 30 seconds).
`cloop_knowledge_embedding_request_duration_seconds` times them.

`cloop_knowledge_embedded_chunks_total` counts what syncs' embedding passes did,
by `kind` and `outcome`: `embedded` (a new vector), `reused` (the document
changed and the chunk's text did not, so it kept its vector), `failed` (sent,
and given no usable vector; it waits for the next sync).

`cloop_knowledge_index_vectors` is how many chunks have a vector from the
configured model, current or waiting for their source's next sync. Only the
leader exports it. Compared with `cloop_knowledge_index_chunks`, it shows the
backfill's progress. It reads 0 while embeddings are off.

```promql
sum(rate(cloop_knowledge_searches_total{retrieval="fallback"}[15m]))
  / sum(rate(cloop_knowledge_searches_total{retrieval=~"hybrid|fallback"}[15m])) > 0.1
sum(cloop_knowledge_index_vectors) / sum(cloop_knowledge_index_chunks)
rate(cloop_knowledge_search_vectors_compared_total[1h]) / rate(cloop_knowledge_searches_total{retrieval="hybrid"}[1h])
histogram_quantile(0.95, sum by (le) (rate(cloop_knowledge_search_vector_scan_seconds_bucket[1h])))
```

A source whose last sync could not embed shows this as its `warning` (in `cloop
knowledge sources`), and `cloop hub doctor` lists such sources under
`knowledge.embeddings.sync`.

## Registry self-monitoring

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_metrics_series_dropped_total` | counter | `metric` |

Described under [Cardinality and the overflow
series](#cardinality-and-the-overflow-series). It should be zero. Any non-zero
value is an instrumentation bug.

```promql
cloop_metrics_series_dropped_total > 0
```

## Adding a metric

1. Declare it in `pkg/hubmetrics/catalog.go`, never at the call site, so the
   whole hub's label schema can be reviewed in one file.
2. Label values must come from a closed enumeration declared in Go source. If
   you can't point to the constant block the values come from, the label is
   unbounded and can't be used.
3. Counters end in `_total`; histograms name their unit.
4. Record it in the same change: call `Inc`, `Add`, `Set` or `Observe` on it
   where the event happens, or name it in the `Families` of a scrape-time
   collector registered in `pkg/ui/hubmetrics.go`. `TestEveryFamilyIsRecorded`
   fails the build for a family that nothing records, because an alert written
   against a family with no samples can never fire.
5. If it is a gauge read from the shared database, export it from the cluster
   leader only (`metricsScrape.leader`), so that `sum()` over members does not
   multiply it.
6. Add a row to this page, or `TestCatalogIsDocumented` fails the build.
