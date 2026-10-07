# Operator runbook

Backup and restore, audit verification, key rotation, upgrade and rollback for a
hosted cloop hub.

Command output below is real. Where a procedure has a sharp edge — an
unrecoverable key, a one-way migration — it is called out at the point where you
would otherwise walk into it.

- [Layout](#layout)
- [Health checks](#health-checks)
- [Backup and restore](#backup-and-restore)
- [Database maintenance](#database-maintenance)
- [Audit chain verification](#audit-chain-verification)
- [The git interception proxy](#the-git-interception-proxy)
- [The Kubernetes access monitor](#the-kubernetes-access-monitor)
- [Key rotation](#key-rotation)
- [Upgrade](#upgrade)
- [Rollback](#rollback)
- [Fleet operations](#fleet-operations)
- [Incident playbooks](#incident-playbooks)

---

## Layout

```
.cloop/
  state.db                                canonical store (SQLite, WAL mode)
  state.db-wal  state.db-shm              WAL sidecars — never copy these by hand
  config.yaml                    0600     operator-written; safe to commit
  hub.env                        0600     CLOOP_SECRET_KEY, CLOOP_UI_TOKEN — never commit
  tls/cert.pem  tls/key.pem      0600     when the hub terminates TLS itself
  backups/state-<UTC>.db                  + a .db.meta.json sidecar per backup
```

Two rules that prevent most of the bad days:

1. **`hub.env` is not a config file, it is the key to every sealed secret.** Back
   it up separately from `state.db` and never in the same place — a backup that
   contains both is a plaintext secret store.
2. **Never copy `state.db` with `cp`.** Use `cloop db backup`, which produces a
   single self-contained file with no `-wal`/`-shm` dependency.

---

## Health checks

| Endpoint | Question | Behaviour |
| --- | --- | --- |
| `/healthz` | is the process alive? | never fails while it can accept a connection — do **not** wire a restart to a slow database |
| `/readyz` | should traffic come here? | three gates: the state database, then the identity provider, then the execution path. Fails during startup, on storage loss, while an issuer has never resolved, and when strict mode leaves no isolating executor registered |
| `/metrics` | Prometheus text | gated: requires the `audit.read` permission, unlike the two probes above |

`/healthz` and `/readyz` bypass auth and rate limiting so a probe can never be
locked out by a flood or a broken IdP. `/metrics` does not — it is an ordinary
authorised route, so a scraper needs a credential carrying `audit.read`. See
[Metrics](metrics.md).

The second and third gates are why a rollout of a misconfigured hub fails
instead of going green.

The identity gate covers the case that used to be invisible: a hub pointed at
an unreachable, misspelled or wrongly-registered issuer came up green and
failed for the first human who tried to sign in. It now resolves the issuer at
startup — discovery and the JWKS fetch — and reports `not_ready` with
`"check": "identity"` for as long as that has *never* succeeded. Once it has
succeeded once the gate stays open: existing sessions keep authenticating
through a later provider outage, and dropping the hub from its Service over one
would turn a login outage into a total one. Set `ui.oidc.require_idp` (or
`cloop ui --require-idp`) to refuse to start outright.

The execution gate is the older one. A hub with `allow_host_process: false` and
no container, Kubernetes or enrolled-agent executor can only answer a run
request with a 409, so it reports `not_ready` and the response body names the
fix:

```json
{
  "status": "not_ready",
  "check": "executors",
  "reason": "strict mode is on (executors.allow_host_process: false) and no isolating executor is registered, so every run would be refused",
  "remediation": "enable executors.container or executors.kubernetes in .cloop/config.yaml, enroll a remote agent (`cloop executor enroll`), or set executors.allow_host_process: true to permit un-isolated host execution"
}
```

The verdict is live, not a snapshot of startup: a hub that boots with nothing
isolating becomes ready the moment an edge device enrolls, with no restart.
An executor that registered but failed *preflight* is degraded, not missing —
it still satisfies this gate, because a cluster that was briefly unreachable
during boot should not keep a hub out of service until someone restarts it.

```console
$ cloop hub healthcheck --url https://hub.example.com --endpoint readyz
$ kubectl -n cloop exec deploy/cloop-cloop-hub -- /usr/local/bin/cloop hub healthcheck --endpoint readyz
```

The image is distroless — no shell, no `curl` — so this command *is* the
container's `HEALTHCHECK` and the Kubernetes exec probe. Options: `--timeout`
(default 3 s), `--ca-file` for a private CA. Exit 0 healthy, 1 not.

### Configuration health: `cloop hub doctor`

`healthcheck` answers "is it up". `doctor` answers "is it configured such that
it will keep working", which is a different question with a different failure
mode: a hub whose certificate expires next week, whose issuer moved, or under
whose RBAC policy nobody is an admin is green on both probes and broken.

```console
$ cloop hub doctor                    # in the hub's directory
$ cloop hub doctor --json | jq '.findings[] | select(.severity=="fail")'
$ cloop hub doctor --offline          # config only; contacts nothing
$ cloop hub doctor --port 8081        # the hub on :8081, with its overlay
```

Where two dashboards share a directory, each takes its hub-scope settings
from its own `.cloop/config.ui-<port>.yaml` merged over `config.yaml`. Pass
`--port` to diagnose one of them as it runs. It defaults to 8080, the port
`cloop ui` serves on without `--port`, so a bare run diagnoses the hub a bare
`cloop ui` starts; `--port 0` reads `config.yaml` alone. Either way the report
names on stderr any overlay it did not merge. See
[two dashboards in one directory](../reference/configuration.md#two-dashboards-in-one-directory).

Every verdict is the hub's own: a check asks the code the hub runs rather than
restating its rule. Whether `cloop ui` would start with `ui.oidc` is
`oidcauth.New`'s answer, whether a redirect path is servable is the rule the
router is built from, whether the git proxy starts is `tlsconf` loading its key
pair and `gitproxy.NormalizeBaseURL` judging its base, and so on. A doctor that
kept its own copies used to fail working hubs — one registered its callback at
`/auth/oidc`, which the hub serves, and was told the hub "only serves the
callback at /auth/callback" — and to pass broken ones.

What it checks, and what each one catches that nothing else does:

| Group | Checks |
| --- | --- |
| `policy` | whether `executors.allow_host_process` was *decided* or merely defaulted |
| `oidc` | whether `cloop ui` would start with `ui.oidc` (`oidc.startup`: the verdict of `oidcauth.New`, the constructor startup runs); the redirect URI — its path by the hub's own rule, so any path under `/auth/` the router can serve passes (an Entra SPA registration is commonly `/auth/oidc`) and only a path the hub refuses fails, saying it will not start — and its origin against `ui.external_url`; issuer discovery, the document's own issuer name, JWKS keys cloop can actually verify with; client secret from the environment rather than the committed config |
| `tls` | cert and key load as a matching pair the way the listener loads them (`tlsconf`), the chain the listener presents is ordered and parses, expiry (warns 30 days out), SANs cover the external hostname, key permissions, and the proxy-termination case — judged by the rule an edge agent applies to `ui.external_url` |
| `ui` | `ui.exposure`: where the process on `--port` actually listens, read from the kernel's socket table, and whether it answers `GET /api/projects` without credentials. **Fail** for a hub without sign-in reachable beyond loopback — whichever build serves it, so a binary from before the loopback default is caught too — or one that would be (a `ui.listen` beyond loopback with `ui.allow_unauthenticated_network`, or one `cloop ui` would refuse to start with); **warn** for a hub with sign-in that serves plaintext beyond loopback while its public URL (`ui.external_url`, else `ui.oidc.redirect_url`) is https. With nothing on the port it judges what `cloop ui --port N` would do; export `CLOOP_UI_TOKEN` from `hub.env` first if the hub uses one |
| `secret_key` | `CLOOP_SECRET_KEY` present, generated key material rather than a passphrase or a placeholder out of the docs, and the key that opens this hub's sealing keys — asked of the keyring the broker opens, read-only (`secret_key.matches`) |
| `rbac` | the mappings parse, the default role's blast radius, group bindings with no `groups` scope, and **whether anybody maps to admin** — all judged on the policy as `authz` normalizes it, so `role: Admin` is admin, and a project-scoped admin is not the hub's |
| `images` | policy validity, whether it constrains registries at all (asked of the policy's own evaluation), digest pinning, cosign installed and its keys readable where the container or Kubernetes executor verifies signatures — and a warning that enrolled devices do not — the operator's own executor images (exempt from the policy, and reported as such), and reachability of the registries the policy names |
| `executors` | reconciliation diagnostics, the strict-mode gate (asked of the check `/readyz` serves), and a liveness probe plus capability report per executor; and each device on the edge channel against this build's place on `main` — a warning past 20 sequences behind, or for a build carrying no sequence, which rollback protection does not cover yet (`executors.edge_lag`) |
| `gitproxy` | whether pushes are brokered at all; whether the proxy would start — its TLS material loaded as the listener loads it, its base judged by `gitproxy.NormalizeBaseURL` — the base sandboxes are pointed at (`advertise_url`, or the bound address as the hub advertises it) and whether only this machine can reach it, plus a bounded dial of it; the branch allowlist and delete authority; and, with the proxy off, any GitHub grant whose branch list therefore cannot be enforced (`gitproxy.branch_grants`) |
| `kubeguard` | whether kubeconfig grants are brokered at all; whether the monitor would start — its TLS material and CA bundle read as the hub reads them, its base judged by `kubeguard.NormalizeBaseURL` — where sandboxes are pointed and whether only this machine can reach it, plus a bounded dial; and the verb ceiling |
| `egress` | whether the broker is on; for each running hub, where its proxy listens and is advertised, or why it would not bind (`egress.hosted`, read from the status every hub records at startup); how each kind of sandbox this hub runs reaches the proxy, by the hub's own routing rules — containers by the bind address (`egress.listen_addr`), Pods and devices by `advertise_addr` (`egress.advertise_addr`) — and a bounded dial of it; and the trap of an `internal: true` filter with no broker to proxy through |
| `storage` | `quick_check`, the schema version against this binary's — the rollback case, naming the build that moved the schema, and failing only where the hub's guard refuses the database (one ahead by additive migrations opens) — whether `CLOOP_ALLOW_SCHEMA_DOWNGRADE` is suppressing that guard, and free space on the volume holding `.cloop` against `orchestrator.min_free_disk_mb`: a warning below twice the floor, a failure below it (`storage.free_space`; see [Disk space low](#disk-space-low)); and the write-ahead log beside `state.db`, a warning once it is larger than 64 MiB and a quarter of the database both (`statedb.wal`, measured before any other check opens the database; see [The write-ahead log](#the-write-ahead-log)) |
| `config` | every value loading had to repair (`config.repaired`): a value reset to its default is a warning, and a section switched off because it could not start as written is a failure — reported under the section's own check for the git proxy, the Kubernetes monitor and the egress proxy, which would otherwise read as "disabled"; and drift between `.cloop/config.yaml` and the copy mirrored in `state.db`, which is what "I changed that setting and nothing happened" usually is |
| `quotas`, `budget` | policy validity, limits set to `0` (which means *none allowed*, not unlimited — except `max_sessions`, where it is no cap), all judged as `quota.New` holds them (a negative ceiling is unlimited); and unbounded spend on a multi-tenant hub, by the daily caps `budget.Enforce` holds a run to — the project's own, read from `config.yaml`, which is where runs read a budget; the host-wide caps in the doctor's `~/.config/cloop` are reported beside them, since they hold back only runs on the host's own driver (an isolated run is not given them); and never counting `monthly_usd`, which nothing enforces |

Exit is 1 on any failure and 0 with only warnings, so it is usable as a
deployment gate. `--strict` fails on warnings too. Every non-pass finding
carries a one-line remediation; the `check` ids in `--json` are stable.

Three of those checks dial rather than read, because `executors.git_proxy.advertise_url`,
`executors.kube_guard.advertise_url` and `executors.egress.advertise_addr` are the only
config values a hub hands to a sandbox and never uses itself — so a value that is right on the hub and unroutable
from a Pod is invisible everywhere else. The dial is bounded (3 s, or `--timeout`)
and never fails the run: the hub is not on the sandbox's network, and for the git
proxy and the Kubernetes monitor a Service name that does not resolve on the hub is
frequently the *correct* setting. (Not for the egress proxy: the hub refuses to hand
Pods a cluster-internal name, and `egress.advertise_addr` fails on one.)
Read `gitproxy.advertise_reachable`, `kubeguard.advertise_reachable` and
`egress.advertise_reachable` as "nothing is listening" versus "this was never
checked" — which were previously the same green line. `--offline` reports them as skipped rather than passing.

Run it twice: once before the first `helm install` or `docker compose up`, and
once in CI against the config repo. `--offline` makes the second cheap.

### Dispatch health: `cloop hub doctor --smoke`

Everything above reads configuration. None of it can catch the failure an
operator actually has after enrolling a device: every check passes, and the
first real task still dies — because the harness image has no shell, or ships
an `ENTRYPOINT` that swallows the argv, or the agent cannot write its
workspace, or the driver drops the credential files it advertised support for.

`--smoke` dispatches a trivial workload through the same primitives a real task
takes and reports each leg separately.

```console
$ cloop hub doctor --smoke                          # every non-cordoned executor
$ cloop hub doctor --smoke --executor edge-01       # one device
$ cloop hub doctor --smoke --json | jq '.smoke[] | select(.first_failure != "")'
```

```
DISPATCH SMOKE TEST
  container (container, isolation container) — 426ms
    ✔ placement      the scheduler would place a task on container
    ✔ workspace      the workload read a file the hub wrote and could write its own
    ✔ lease          the sandbox opened the leased credential file and it held this run's material
    ✔ dispatch       the workload ran in the sandbox and exited 0
    ✔ logs           streamed 130 bytes, complete and correctly attributed
    – write_back     this backend shares its workspace with the hub, so there is nothing to write back
    ✔ revocation     the credential was destroyed and the lease no longer renews
    ✔ cleanup        every container, credential and directory this run created was removed
    the dispatch circuit works end to end
```

| Stage | What a failure means |
| --- | --- |
| `placement` | the scheduler would not choose this executor at all — host-execution policy, a cordon, or an agent below `executors.min_agent_build` |
| `workspace` | the sandbox got no usable working directory; on a filesystem-sharing driver, that it could not see a file the hub wrote |
| `lease` | a throwaway credential was minted, granted and delivered — a failure names the delivery path, not the grant |
| `dispatch` | the workload did not start or exited non-zero; the last lines of its own output are in `--json` under `details.output` |
| `logs` | output did not come back, was truncated, dropped chunks, or **carried another run's id** — the last is a confidentiality problem on a multi-tenant hub, not a logging bug |
| `write_back` | a driver asked for a write-back produced no result, so a task's commits would be made in the sandbox and silently lost |
| `revocation` | the credential outlived its lease — verified by stat-ing the files and asking the broker to renew, not assumed |
| `cleanup` | something this run created could not be removed |

A stage reports `skip`, never `pass`, when it does not apply to the backend or
cannot be proved hermetically — `write_back` on a driver whose workspace *is*
the hub's directory, `lease` on a driver that cannot take a credential back.
"We did not look" and "we looked and it was fine" are different answers.
Today `write_back` is skipped everywhere: a write-back is measured against the
commit the sandbox's tree was built from, which needs a tree the driver built
from git, and the smoke's workload runs in a plain directory. A run of a
project with a git workspace — or of a feature — exercises it.

**It is safe against production.** The workload touches no network, clones no
repository and calls no model. The credential it mints is a kubeconfig pointing
at `127.0.0.1:1`, its TTL is measured in seconds, and it is destroyed and
*verified destroyed* before the command exits. Everything else — container,
workspace, lease directory, and the secret and grant rows — is removed on every
exit path, including ctrl-C. Anything it could not remove is named in the report
and exits 5.

**Exit codes**, so it works as a Kubernetes readiness gate and a post-deploy CI
step without parsing JSON:

| Code | Meaning |
| --- | --- |
| 0 | every target smoked clean |
| 1 | a configuration check failed (the hub is misconfigured regardless of dispatch) |
| 3 | no executor to dispatch to — *not* the same as healthy |
| 4 | an executor failed a stage |
| 5 | the run could not clean up after itself; needs a human |

The default sweeps every non-cordoned executor, so "which of my ten devices is
broken" is one command. Cordoned and draining devices are skipped — and the
report says which, because a clean verdict over seven of ten devices is worse
than no verdict. Naming one with `--executor` smokes it anyway, which is how
you check whether a cordoned device is fixed before returning it to rotation.

As a readiness gate, note that it starts a container per executor: point a
liveness probe at `/healthz` and use this on a timer or after deploys, not on
every kubelet poll.

---

## The control-plane lease

**Several hubs may serve one `state.db`, as members of one cluster.** Every
`cloop ui` joins the control plane at its working directory; start more in the
same directory, or raise `replicaCount` in the Helm chart, and they serve the
same state behind one load balancer. They share the database, forward to each
other what only one of them can answer, relay live events between their
dashboards, and elect one leader for the work that must happen exactly once.
[Hub cluster](../architecture/hub-cluster.md) describes how.

The lease is the leader's. Whoever holds it runs retention, backups,
auto-resume, the session janitor and the periodic orphan sweep; the other
members serve everything else.

```console
$ cloop hub cluster status
Hub cluster
  /srv/cloop/.cloop/state.db

  hub_59f28a07ceea8b8fa2b4386edc1cef40 leader  serving
      host hub-1 pid 1234, listening :8080, reachable at http://127.0.0.1:8080
      version v0.9.0, started 2026-09-12T17:23:15Z
  hub_d74093a016f4198a7ec530075841bd4f  serving
      host hub-1 pid 1301, listening :8081, reachable at http://127.0.0.1:8081
      version v0.9.0, started 2026-09-12T17:25:02Z

  2 member(s) serving

$ cloop hub lease status
Control-plane lease
  /srv/cloop/.cloop/state.db

  state      held
  instance   hub_59f28a07ceea8b8fa2b4386edc1cef40
  host       hub-1 (pid 1234)
  serving    :8080
  acquired   2026-09-12T17:23:15Z
  last beat  11s ago
  lapses in  49s if the holder stops renewing
```

### How it behaves

| Situation | What happens |
| --- | --- |
| Clean shutdown (SIGTERM, `helm upgrade`, `systemctl restart`) | The member hands over its runs and agents, releases the lease if it led, and leaves. Another member — or the restarted process — leads within seconds. |
| A member killed outright (SIGKILL, OOM) — same host | The others probe its recorded pid and take over at once: its runs are adopted, and if it led, a new leader is elected. |
| A member gone on another host or node, in another container, or after a reboot | The pid cannot be trusted. The member is judged dead after 20s of silence and its runs adopted; the lease, if it led, lapses on its **last heartbeat + 60s**. |
| A leader paused past the TTL and its lease taken | It steps down and keeps serving as a member. |
| A second hub started deliberately | It joins as a member. |
| A hub from before clustering holds the lease | A current build refuses to start beside it — see below. |

Nothing here needs an operator in the normal case, including the crash case.
A stale lease is free, so a dead hub cannot wedge its own restart.

### When a hub refuses to start

Two situations make a hub refuse rather than join.

**A hub from before clustering is serving.** It holds the lease without being a
member, so it would neither forward requests to a new member nor see its events:

```
Error: another cloop hub controls this state and cannot share it

  holder     hub_59f28a07… on hub-1 (pid 1234), serving :8080
  version    v0.8.2
  last beat  4s ago
```

Upgrade or stop it. A restart does that: the old process releases the lease on
the way out. If it was killed rather than stopped, a new build on the same host
probes its pid and starts at once; elsewhere its lease has to lapse first —
within a minute.

**`ui.cluster.exclusive` is set**, on this hub or on the one already serving.
That is the pre-cluster rule on request — one process, guaranteed — and the
refusal names the member that is serving. Stop it, or remove the setting to let
them join.

In either case:

1. `cloop hub cluster status` and `cloop hub lease status` — who is serving and
   who holds the lease? Is the holder this machine, and is its pid alive?
2. If you meant to run one hub, stop the other. Under Kubernetes look for a
   Pod of an older release.
3. If the holder is genuinely gone, wait for `lapses in` to reach zero.
   `cloop hub lease clear` releases a lapsed lease explicitly, and refuses while
   the lease is live. There is no `--force`: a live lease means a hub is
   renewing it right now.

---

## Backup and restore

### Backup

`VACUUM INTO` under a read transaction: safe while the hub is running and while
tasks are executing.

```console
$ cloop db backup
cloop db backup
  source: /srv/cloop/.cloop/state.db
  output: /srv/cloop/.cloop/backups/state-20260822T095227Z.db

  WAL checkpoint:  TRUNCATE log_frames=0 checkpointed=0
  size:            320.0 KB
  duration:        19ms
  sha256:          bbedb9d5f45fd4bf8fb368b60c29c7cb7cb60d3dac608229cf1bcee5d63292ed
  schema version:  15
  metadata:        /srv/cloop/.cloop/backups/state-20260822T095227Z.db.meta.json

Backup complete.
```

`--output <path>` overrides the destination. The `.meta.json` sidecar records the
SHA-256, size, source, schema version and duration; restore checks the digest
against it. Keep the sidecar with the backup — losing it costs you the integrity
check, and restore will then need `--skip-checksum`.

A backup contains **sealed** secrets. It is not plaintext, but it is one half of
a plaintext secret store; the other half is `hub.env`.

Nightly, with retention:

```bash
cloop db backup --output /var/backups/cloop/state-$(date -u +%Y%m%dT%H%M%SZ).db
find /var/backups/cloop -name 'state-*.db*' -mtime +30 -delete
```

### Restore

```console
$ cloop db verify                                   # check the live db first
$ cloop db restore /var/backups/cloop/state-20260822T095227Z.db --force
```

`--force` is required when a live database is present. Before overwriting,
restore moves the existing file aside as `.pre-restore.<UTC>` — so a restore of
the wrong backup is itself reversible. `--skip-checksum` proceeds without the
metadata sidecar.

Restore validates with `PRAGMA integrity_check`, the SHA-256, and a schema sanity
check before it writes anything.

**Restoring a hub is a two-part operation.** Restoring `state.db` alone gives you
a database full of secrets you cannot unseal. Restore the matching `hub.env`
(specifically `CLOOP_SECRET_KEY`) too, or every stored secret is lost.

Order of operations for a full restore:

1. stop the hub (do not restore under a running process)
2. restore `hub.env` — the matching `CLOOP_SECRET_KEY`
3. `cloop db restore <backup> --force`
4. `cloop db verify`
5. start the hub, confirm `/readyz`
6. `cloop audit-log verify`
7. `cloop executor ls` — enrolled agents reconnect on their own backoff

---

## Database maintenance

```console
$ cloop db verify            # integrity_check + foreign_key_check (read-only)
$ cloop db verify --quick    # quick_check — faster, less thorough
```

Exit codes: 0 pass, 1 issues found, 2 the check could not run.

```console
$ cloop db maintain --dry-run
cloop db maintain — dry-run (size report only)
  database: /srv/cloop/.cloop/state.db

  size before:    541.9 MB (138739 pages, 4096 bytes/page, 38740 freelist)
  wal before:     152.2 MB
  last maintenance: 504h12m40s ago (vacuum+analyze, freed 1.96 GB)

Dry run — no changes written.
  estimated reclaim: 151.3 MB (freelist_count × page_size)
  write-ahead log:   152.2 MB (a real run truncates it)
$ cloop db maintain                         # with the hub stopped
cloop db maintain — VACUUM + ANALYZE
  …
  size after:     390.6 MB (99999 pages)
  wal after:      0 B (truncated)
  operations:     [VACUUM ANALYZE]

Reclaimed 151.3 MB.
```

`cloop db maintain` runs `VACUUM` + `ANALYZE`, records the run in
`maintenance_log`, and ends by truncating the write-ahead log, which the
`VACUUM` has just put every page of the database through. `--auto` skips
unless the database has grown more than 20 % since the last vacuum, which is
what you want in a cron entry:

```bash
0 4 * * *  cloop db maintain --auto
```

`VACUUM` rewrites the database and needs free space roughly equal to its size —
twice that while it runs, since the rewritten pages pass through the log
before the closing checkpoint gives them back.

### The write-ahead log

`state.db-wal` is where every write to the database goes first; a checkpoint
copies it into `state.db`. In steady state it is a few megabytes. SQLite reuses
the file from its start after each checkpoint but never shrinks it, so a burst
of writes — a `VACUUM`, which writes the whole database through it, or a bulk
delete by row retention or `cloop hub audit prune` — used to leave the log at
that size for as long as anything had the database open: on 2026-10-06 this
project's hub had a 340 MB log beside a 409 MB database, on a disk 98% full.
Three things keep it bounded now (Task 20392):

- **Every read-write connection trims it.** cloop opens its databases with
  `journal_size_limit` at 64 MiB, so whichever connection starts the log over
  after a checkpoint cuts the file back to 64 MiB, or to the size of its own
  write if that is larger. On a busy hub that is within seconds of the burst
  ending — but only connections from this version on do it. Older builds
  sharing the database (a long-lived `cloop run`, a second dashboard started
  from an older binary) write without the limit.
- **The leader truncates it.** The hub that leads runs
  `PRAGMA wal_checkpoint(TRUNCATE)` at the end of every retention pass — on
  every project's database, not only its own — and every minute while its own
  database's log is over 64 MiB. The checkpoint waits at most 250 ms for other
  connections: a TRUNCATE checkpoint holds the write lock while it waits, so
  the policy's usual 5 s would hold every writer up for as long and fail
  writers whose own 5 s ran out. It copies the log back with a PASSIVE
  checkpoint first, which takes no lock a writer waits on, so the TRUNCATE has
  little left to copy while it holds one. If a connection is still reading from
  the log, it reports busy, nothing changes, and the next minute tries again;
  the hub logs the first busy attempt and one an hour after that:

  ```
  retention [/srv/cloop] write-ahead log is 324.2 MB, over the 64.0 MB limit, and another connection was still using it after 250ms (1 attempt(s) so far); retrying every 60 s
  retention [/srv/cloop] truncated the write-ahead log, 324.2 MB → 0 B, after 3 busy attempt(s)
  ```

- **`cloop hub retention --apply` truncates it** with the same short wait,
  beside a running hub or not, and **`cloop db maintain`** ends every run that
  goes ahead — which needs the hub stopped — the same way.

How to see it: `ls -l .cloop/state.db-wal`, the `cloop_statedb_wal_bytes` gauge
([metrics](metrics.md#control-plane-database)), and `cloop hub doctor`'s
`statedb.wal`, which warns once the log is larger than both 64 MiB and a
quarter of the database. `cloop db maintain` prints `wal before:` and
`wal after:`.

**A log that stays large** is held by something. Either a connection keeps a
read transaction open the whole time — the leader's minute-by-minute attempts
then all report busy, and its log says so hourly — or every connection writing
the database predates the limit. `fuser -v .cloop/state.db-wal` lists the
processes with the log open; the version of each is in `/proc/<pid>/exe`
(`go version -m`). Until the older ones are replaced, the leader's checks are
what keep the file down. If no hub is running, `cloop hub retention --apply`
truncates it.

### A task row that will not load

Three task columns decide what runs: `depends_on`, `on_success` and
`on_failure`. If one of them holds something that is not a JSON list — a
truncated write, a restored backup, a hand edit — every load of the project
fails and names the row, instead of reading the value as "no dependencies" and
releasing the task early:

```
task 7: column depends_on is not decodable JSON ("[1,2"): statedb: corrupt task column: unexpected end of JSON input
```

A save refuses to go ahead too, because it replaces every stored task and
would delete or overwrite the one the error names — so a run in progress stops
at its next write rather than carrying on with work it can no longer record
(see "A run stopped: run progress could not be saved" below). Back up, then
write the list you want:

```console
$ cloop db backup
$ sqlite3 .cloop/state.db "UPDATE plan_tasks SET depends_on = '[1,2]' WHERE id = 7"
```

A damaged `tags`, `annotations` or `links` value does not stop the load: the
field reads as empty and the hub logs `statedb: task N: column C is not
decodable JSON, field dropped` once per damaged value.

Migration 0054 adds columns that `cloop migrate` or a development build may
already have created. It adopts one only if it matches the declared column
exactly; otherwise startup fails with `plan_tasks.<column> already exists as
<what is there>, but this migration declares it <what 0054 wants>`. Check what
the column holds, then drop it (`ALTER TABLE plan_tasks DROP COLUMN <column>`)
or rebuild it to match, and start cloop again.

---

## Disk space low

A run will not start work on a disk too full to record it (Task 20381). Before
every task attempt and every evolve round it measures the volume holding the
project's `.cloop` and the working tree's volume; below
`orchestrator.min_free_disk_mb` (default 1024 MB) nothing starts and the run
pauses with reason `disk_low`.

**What you see.** The project reads *Paused: volume / has 812.3 MB free, below
the 1.00 GB floor* — with a **Stop** button, because the run is still up: it
measures again every minute and carries on by itself once every volume is back
above the floor plus a tenth (1.1 GB with the default). The event history has a
`session_paused` row with `pause_code: disk_low`, the volume, the free bytes,
the floor and what was about to start; a `session_started` row "Run resumed:
disk space recovered" follows when it carries on. In parallel mode the round in
flight finishes and records its outcomes first; no new task starts. Admins also
see a banner across the dashboard while the **hub's own** state volume is below
the floor, `cloop hub doctor` fails `storage.free_space`, and
`cloop_hub_disk_free_bytes{volume}` shows the trend — alert on it at twice the
floor, before runs start pausing.

**What to do.** Free space on the volume the message names; the run notices
within a minute. The usual places, largest first on a busy hub:

```console
$ df -h /                                   # what the run measured
$ ls -l .cloop/state.db-wal                 # the write-ahead log; see "The write-ahead log"
$ cloop hub retention                       # dry run: what the janitor would reclaim
$ cloop hub retention --apply               # ...and reclaim it, including VACUUM and the log
$ cloop compact --dry-run                   # per project: old artifacts, snapshots, checkpoints
$ go clean -cache                           # on a build host: often gigabytes
$ du -sh /tmp/* 2>/dev/null | sort -h | tail # test runs leave scratch here
```

Check what a file in `/tmp` belongs to before deleting it (`lsof +D`): another
run's work may be in it. To end the wait instead, press Stop — the pause is
recorded as stopped while waiting for disk space, and the next Run checks again.

**The reserve.** Each project keeps `.cloop/reserve`, 16 MiB of preallocated
blocks, put in place whenever the check passes. If the disk fills between the
check and a task's verdict or outcome write anyway — a task's own build is the
usual cause — the run deletes the reserve, writes again on the space that frees,
and then pauses `disk_low` before starting anything else. Its pause detail
then begins "task #N's verdict only reached the disk by releasing the 16.0 MB
free-space reserve". The reserve comes back by itself at the next check that
has room. Only if the second write fails too does the run stop with
`state_not_persisted` — free space, then Run; the next run recovers the tasks
that one left in progress. The reserve is not data: snapshots, `cloop compact`,
the janitor and the disk-usage reports leave it out, and deleting it by hand is
harmless.

**Tuning.** Set the floor in **Settings → Disk & Retention** (admins), with
`cloop config set orchestrator.min_free_disk_mb <MB>`, or in a project's
`config.yaml`. `0` turns the check and the reserve off — the hub doctor then
warns, because a full disk goes back to corrupting outcomes. A run of the hub's
own directory gets the Settings value even when it lives in the per-instance
overlay; every other project's run reads its own `config.yaml`. See
[Free-space floor](../reference/configuration.md#free-space-floor).

A run killed while it waited (an OOM kill, a host reboot) leaves the waiting
pause behind; the hub settles it as *previous run ended unexpectedly* when it
notices, exactly as for a stale "running".

## Audit chain verification

`audit_events` is hash-chained: each row's `row_hash` covers its content and the
previous row's hash. Editing or deleting a row breaks the chain from that point.

```console
$ cloop audit-log verify
OK — 8 events verified
```

Exit 0 intact, 2 broken — and on a break it names the row id and the reason.
**Run this on a schedule and alert on exit 2**; a chain break is either
corruption or tampering, and both want a human.

What the chain does and does not prove: it detects modification and insertion
anywhere in the history, and deletion anywhere except the tail. Truncating the
newest rows leaves a shorter, still-valid chain. Regular export off-box is what
closes that gap.

```console
$ cloop audit-log list --entity secret --since 7d
$ cloop audit-log list --actor alice@example.com --type run.start --json

$ cloop audit-log export --format jsonl --since 24h --verify --output /var/log/cloop/audit.jsonl
$ cloop audit-log export --format cef  --since 24h --verify | logger -t cloop -p local0.notice
```

| Format | Use |
| --- | --- |
| `jsonl` | lossless, structured payloads — the archival format |
| `csv` | flat table for spreadsheets |
| `cef` | ArcSight Common Event Format, syslog-ready |

### Reconstructing one task

The question an auditor actually arrives with is about a single piece of work:
*which executor ran task 63, under which secret leases, and how did it end?*

```console
$ cloop audit-log --task 63
Task #63 — Provision the staging cluster
2 execution(s) recorded

── run 1/2  run_0123456789abcdef0123456789abcdef
   executor    edge-pi4  kind=remote  isolation=remote
   actor       alice@example.com
   image       ghcr.io/acme/harness@sha256:3f1a…
   sandbox     spec sha256:9c4e0b1a7d22
   leases      lease-7f3c
               2026-09-15 09:14:02  secret.lease  gh-deploy-key
   outcome     failed  after 1m30s
   reason      terraform apply exited 1: quota exceeded in eu-west-1
```

This reads `audit_events` and **no other table** — not the plan, not the task
record. That restriction is the point rather than an implementation detail: an
auditor reviewing an incident has an exported trail, not a live database, and a
reconstruction that needed the hub's working state would be unusable exactly
when it is needed. `pkg/statedb` has a test that drops `plan_tasks` before
reconstructing, so the guarantee cannot quietly regress.

The join it performs is on the **run id**, which every dispatch, terminal and
lease row carries. A task id is not enough: task 63 above ran twice, and each
execution held a different credential. Joining credentials to the task id would
report that it held both, throughout — which is how a narrow finding becomes a
wrong one.

| Event | Written when |
| --- | --- |
| `task.dispatch` | a task enters execution — executor, isolation, pinned image digest, sandbox spec hash, lease ids, actor |
| `task.finish` | it leaves execution, by *any* path: signal, kill, timeout, provider abort, or a hub crash reconciled later — outcome, duration, reason |
| `task.status` | a human flips a status from the dashboard or the CLI, naming them |

`task.finish` is emitted where the status is persisted rather than at each of
the orchestrator's exit paths, so an exit path added later cannot forget it.
A run still in flight — or one whose hub died so hard it never wrote a terminal
row — shows as `no terminal row` rather than being given an invented outcome.

### Retention: keeping the trail bounded

The trail only grows, and on a busy hub it grows fast enough to matter — this
project's own control plane reached 1.1M rows and 2.4 GB. Retention moves the
old prefix out of the database without breaking verification.

It is **opt-in**. With no `audit.retention_days`, nothing is ever pruned.

```yaml
audit:
  retention_days: 90            # 1–3650; 0 or absent keeps everything
  export_dir: /srv/audit-archive # default: .cloop/audit-archive
  prune_on_maintain: true       # let `cloop db maintain` apply it
```

A prune never simply deletes. It streams the prefix to a JSONL archive,
chain-verifies every row on the way out, digests the file, and only then
removes the rows — recording an *anchor* holding the boundary hash, the id the
chain resumes at, and the archive's SHA-256.

```console
$ cloop hub audit prune --before 90d --dry-run
$ cloop hub audit prune --before 90d
$ cloop hub audit anchors        # every truncation, oldest first
$ cloop hub audit verify-seals   # re-hash each archive against its anchor
```

After a prune, `cloop audit-log verify` walks *across* the gap using the anchor
and still reports OK. That is not a relaxation: the anchor pins the id the
chain must resume at, so deleting a few more rows just past the boundary is
still caught.

Three things worth knowing:

- **Pruning does not shrink the file.** It frees pages onto SQLite's freelist.
  Run `cloop db maintain` to return them to the filesystem. That command
  VACUUMs, which rewrites the whole file, so it **refuses while any hub is
  serving the control plane** — stop the members (`cloop hub cluster status`
  lists them) or wait for the lease to lapse (`cloop hub lease status`).
- **`verify-seals` is the check that leaves the database.** Chain verification
  can only prove the survivors agree with what the anchors claim, and anyone
  who can rewrite `audit_events` can rewrite `audit_anchors` too. Copy the
  archives somewhere the hub cannot write; that copy is the real evidence.
- **A pruned trail can no longer be replayed from the beginning.**
  `cloop events replay` refuses rather than silently rebuilding a partial
  database, and names the archive holding the missing events. Pass
  `--allow-truncated` to rebuild just the surviving tail on purpose.

`--verify` refuses to export a broken chain, so an exported file is one that
passed verification at export time. Every format carries `prev_hash` and
`row_hash`, letting the recipient re-verify independently. Filters: `--actor`,
`--entity`, `--entity-id`, `--type`, `--since`, `--until`, `--limit`. Output files
are written 0600.

Audit rows never contain credential material — that is asserted by
[five separate checks](../security/model.md#secret-non-disclosure--secrets_testgo-audit_testgo-uiroutes_testgo),
including one that scans *every* row rendering rather than a sample.

---

## The git interception proxy

Off by default. With it on, a sandbox that fetches and pushes the project's
source never holds the forge PAT — it gets a session token for a proxy the hub
runs, which enforces the branch allowlist on the push's own ref-update list. The
design is in [git interception proxy](../git-interception-proxy.md); this is the
operational part.

### Turning it on

1. **Give it a certificate the sandbox will accept.** This is the step that gets
   missed: the certificate is validated by *the sandbox's* git, not by the hub.
   A public-CA certificate needs nothing further; a self-signed or private-CA one
   needs its CA in the sandbox image's trust store, or in a bundle named by
   `SSL_CERT_FILE` / `GIT_SSL_CAINFO` on the machine git runs on. A Pod gives you
   neither, so on Kubernetes the driver mounts the CA from a ConfigMap and trusts
   it for the proxy's URL only:
   [`executors.kubernetes.git_ca_bundle`](../reference/configuration.md#on-kubernetes-the-git-proxys-ca-for-its-url-only).
2. **Decide what the sandbox can reach.** `listen_addr` is the bind address;
   `advertise_url` is what becomes the sandbox's remote, and it has to route
   from where git actually runs — a Service for the Kubernetes backend, the
   hub's address on the link for an edge device. The
   [table of forms](../git-interception-proxy.md#advertise_url-what-the-sandbox-can-reach)
   covers the rest.
3. **Write the section and restart the hub.**

   ```yaml
   executors:
     git_proxy:
       enabled: true
       listen_addr: "0.0.0.0:8443"
       advertise_url: "https://hub.internal:8443"
       cert_file: /etc/cloop/tls/git-proxy.crt
       key_file: /etc/cloop/tls/git-proxy.key
       session_minutes: 60
   ```

4. **Confirm it came up.** One line on stderr names the bind address, what
   sandboxes are pointed at, and the allowlist:

   ```
   ui: git interception proxy on 0.0.0.0:8443, advertised as https://hub.internal:8443; pushes limited to refs/heads/cloop/**
   ```

5. **Run one task on the executor** and check the audit trail for the session and
   the fetch: `cloop audit-log list --entity gitproxy --since 1h`.

**With the Helm chart** the steps above are values: `executor.gitProxy.enabled`
and a certificate from `executor.monitorTLS` (`selfSigned`, or an
`existingSecret` from cert-manager plus a way for the Pods to trust its CA). The
chart advertises the proxy at the hub's Service name, adds the port to the Pod
and the Service, and renders `git_ca_bundle` with the CA in a ConfigMap in the
workload namespace; see
[deploy/README.md](../../deploy/README.md#the-git-proxy-and-the-kubernetes-access-monitor).
That configuration is what CI's kind cluster runs a Pod through on every push
([`tests/kube`](../../tests/kube/README.md)).

Two failure lines matter, and both mean GitHub access has stopped rather than
been opened up. After `ui: git interception proxy NOT started: …` every git
workspace that needs a credential is refused with `ErrWorkspaceUnavailable`, and
every GitHub grant is left out of the leases it would have been part of instead
of being handed to the sandbox; `ui: executor <id> is NOT routed through the git
proxy: …` does the same to one executor's workspaces. The hub deliberately still
boots, so these are worth alerting on rather than relying on a failed start. A
third, `ui: git proxy decisions will go to stderr, not the audit trail: …`, is
smaller: the proxy still refuses what it should, the evidence just is not in the
database.

The failure to watch hardest for prints no `ui:` line at all. A section with
`enabled: true` that the configuration loader cannot use — no `cert_file` or
`key_file`, an unusable `listen_addr` or `advertise_url` — is switched off at
load with a `warning: config executors.git_proxy.…` line, and the hub then runs
exactly as one with no proxy: credentials are delivered into sandboxes as
before. After enabling the section, the `ui: git interception proxy on …` line
from step 4 is the proof, and its absence is the alarm. See
[how it fails](../architecture/git-proxy.md#how-it-fails).

### Session lifetime is not run lifetime

A **workspace** session — the one cloop's own fetch and write-back use — lives
for `session_minutes` (60 by default, 720 maximum) from *dispatch*, and nothing
closes it when the run ends. **A run that outlives its session fails its push**
with an authentication error from git and a `gitproxy.rejected` row. Set the TTL
against the longest run the hub is expected to finish, not the median one.

A session minted for a GitHub **lease** — the one the workload's own git uses —
ends with its lease or at its own `session_minutes`, whichever is first: when the
run ends, when the lease is revoked from the Secrets panel or `POST
/api/leases/{id}/revoke`, and when the lease lapses. A run's lease is issued for
15 minutes and extended in place while the run is live, so it lapses only when
the run is gone or a grant it holds was revoked or expired; the janitor then
sweeps it within a minute, closing the session. Each extension is a
`secret.renew` row, and a refused one — the grant was revoked — is a denied
`secret.renew` naming the grant. See
[how long a session lives](../architecture/git-proxy.md#how-long-a-session-lives).

A workspace session ends early when its lease is revoked: since Task 20390 the
lease it stands on is kept alive while it lives and listed with the hub's other
leases (`GET /api/leases`, the Secrets panel), and revoking it there closes the
session at once. A hub restart suspends a recorded session rather than closing
it — a guarded one, the one a GitHub lease is delivered as, and a workspace one
whose lease is recorded — and the process that adopts its run restores it (see
[after a control-plane restart](#after-a-control-plane-restart)); one with no
record is closed, as `gitproxy.session_closed` with the reason *"the hub is
shutting down"*. Short of that a session expires on its own TTL, which is
enforced at authentication whether or not the five-minute reaper has swept it.
Revoking the underlying grant with `cloop secret revoke` stops the *next*
dispatch from minting anything; rotate the PAT at the forge as well.

The lease keepalive does not stretch the GitHub App **token** a session presents
upstream, which GitHub honours for an hour: the session renews that itself, at
the grant's original scope, when about ten minutes are left (Task 20375). So with
a `github_app` grant `session_minutes` is the only ceiling on a session's life,
as it is with a PAT. See
[GitHub App tokens past their hour](#github-app-tokens-past-their-hour).

### GitHub App tokens past their hour

A `github_app` grant's installation token expires an hour after it is minted, and
the hub replaces it before then, at exactly the scope of the first — under the
proxy from the session's request path, without it from the lease keepalive,
which rewrites the sandbox's `github-token` file in place. The full behaviour is
in [the secrets guide](../guides/secrets.md#keeping-the-token-past-githubs-hour).
When a long run loses GitHub anyway, it is one of these, and the audit trail says
which:

```console
$ cloop audit-log list --type secret.renew --since 24h --json      # re-mints, and refusals
$ cloop audit-log list --type lease.refresh --since 24h --json     # deliveries to the executor
$ cloop audit-log list --type github_app.token_destroy --since 24h # superseded and refused tokens
$ cloop audit-log list --type gitproxy.session_closed --since 24h  # sessions a refusal closed
```

| What you see | What happened | What to do |
| --- | --- | --- |
| a denied `secret.renew` naming a revoked or expired grant | the grant behind the token was withdrawn; its tokens were destroyed and, under the proxy, the session closed | nothing, if intended; re-grant otherwise |
| a denied `secret.renew` quoting GitHub (*suspended*, *not accessible to the installation*, 401) | GitHub refused the re-mint for good: the installation was suspended or uninstalled, a repository was removed from it, the App's key was deleted | fix the App installation, then start the run again |
| denied `secret.renew` rows saying *will retry* | GitHub was unreachable, rate-limiting or answering 5xx; the held token kept working while the hub retried each minute | check the hub's route to `api.github.com`; access ends only if this outlasts the token |
| a denied `lease.refresh` and a `credential_refresh` journal row naming the agent's protocol | the device's agent is older than v17, so it was not sent the new token; the run kept its first token until it expired | upgrade the agent to the hub's build (the row says how) |
| a denied `lease.refresh` naming `"patch"` | a Kubernetes executor's Role predates the `patch` verb on `secrets` | add `patch` to the Role's secrets rule (the shipped chart has it) |
| a denied `lease.refresh` saying the agent is not connected | the device was offline when the token was due | the keepalive retries each minute while the old token lasts |

A refresh does not cross members of a [hub cluster](#the-control-plane-lease): the
keepalive runs on the member that issued the lease, and reaches the agents
connected to that member. A device whose agent reconnected to another member
mid-run keeps its token until it expires.

### Alert on `gitproxy.push_denied`

```console
$ cloop audit-log list --type gitproxy.push_denied --since 7d
$ cloop audit-log list --entity gitproxy --since 24h --json
```

A `push_denied` row is a sandbox that tried to move a ref outside its allowlist —
`refs/heads/main`, say — and was refused before anything was forwarded to the
forge. It is the only place that attempt is written down; nothing else in cloop
records it, because without the proxy nothing else is on the path.

It is not a noisy signal to be tuned away. A well-behaved task never produces
one, so each occurrence is either a workload doing something it was not asked to
do or a policy narrower than the task it was minted for, and both want a human.
Its sibling `gitproxy.push_allowed` is emitted *before* forwarding, so a
`push_allowed` with no matching change on the forge means the forge refused it —
branch protection, a non-fast-forward — not that the proxy did.

---

## The Kubernetes access monitor

Off by default. With it on, a kubeconfig granted to a project stays in the hub:
the sandbox's `kubectl` gets a kubeconfig naming the monitor and a session token,
and every request is decided against the grant's verbs and namespaces before the
cluster credential is attached. A grant with no verbs is read-only. The design is
in [Kubernetes access monitor](../architecture/kubernetes-access.md); this is the
operational part.

### Turning it on

1. **Certificate.** Unlike the git proxy, nothing has to change in the sandbox
   image: the monitor embeds its CA (`ca_file`, else `cert_file`) in every
   kubeconfig it issues.
2. **Reachability.** `advertise_url` becomes the kubeconfig's `server:`, so it
   has to route from where `kubectl` runs — the hub's Service for Pods.
3. **Write the section** (`executors.kube_guard`; the
   [reference](../reference/configuration.md#kubernetes-access-monitor) has every
   key) and restart the hub, or with the Helm chart set
   `executor.kubeGuard.enabled=true` beside `executor.monitorTLS`.
4. **Confirm it came up:**

   ```
   ui: kubernetes access monitor on 0.0.0.0:8444, advertised as https://cloop-hub.cloop.svc:8444; policy floor no verb ceiling
   ```

5. **Check it from a sandbox.** Grant a project a kubeconfig with
   `--namespaces team-a` and no verbs, run a task, and look for
   `kubeguard.session_minted` and — when the task writes — a
   `kubeguard.request_denied`: `cloop audit-log list --entity kubeguard --since 1h`.

Its failure lines mirror the proxy's: `ui: kubernetes access monitor NOT started:
…` means kubeconfig leases are refused, not delivered unguarded.

What is proven, and where: on every push CI installs the Helm chart on kind with
the monitor on, grants a project a kubeconfig that may edit a namespace with no
verbs, and runs a task whose Pod's `kubectl get pods` is forwarded and whose
`kubectl create configmap` is refused by the monitor — both audited, nothing
created, no cluster token readable in the Pod — on one replica and on a hub
cluster of three ([`tests/kube`](../../tests/kube/README.md)). The git proxy is
proven in the same run.

### Alert on `kubeguard.request_denied`

```console
$ cloop audit-log list --type kubeguard.request_denied --since 7d
```

A task doing what it was asked never produces one, so each is a workload writing
to, or reading outside, what it was granted — or a grant narrower than its task.
Allowed requests are not recorded unless `executors.kube_guard.audit_allowed` (in
the chart, `executor.kubeGuard.auditAllowed`) is on; then each forwarded request
is a `kubeguard.request_allowed` row naming verb, resource and namespace. Turn it
on where the trail has to say what a sandbox *read*; expect a burst of rows per
`kubectl` invocation and one per watch.

---

## Key rotation

Three different keys, three different procedures. The sealing key rotates
online with `cloop hub key rotate`; the TLS key rotates in a staged overlap; the
dashboard token rotates by replacement and causes a logout.

### TLS certificate and agent pins — supported, staged

Agents pin the hub's **SPKI** (a hash of the public key), not the certificate. So
a routine renewal that reuses the key does **not** change the pin, and an
enrolled fleet survives renewal with no action.

```console
$ cloop hub pin                          # from ui.tls.cert_file
$ cloop hub pin --cert /path/new.pem     # the pin of a certificate you are about to roll onto
```

Rotating onto a **new key** does change the pin. Stage it — agents accept a
comma-separated pin set precisely so the two can overlap:

1. `cloop hub pin --cert new.pem` to get the incoming pin
2. distribute `--pin <old>,<new>` to agents and restart them
3. roll the hub onto the new certificate
4. confirm `cloop executor ls` shows every agent reconnected
5. redistribute with only `<new>`

Reversing steps 2 and 3 locks every agent out. `cloop hub tls-init` generates a
self-signed certificate for development only.

The [git proxy](#the-git-interception-proxy) has its own `cert_file` and
`key_file` and is not covered by any of the above. Nothing pins it, but its
certificate is validated by every sandbox's git, so a rotation onto a new CA has
to reach the sandbox image's trust store *before* the hub starts serving it —
otherwise the first symptom is every provisioning fetch failing to verify the
peer.

### Dashboard token (`CLOOP_UI_TOKEN`) — manual, causes a logout

Generate 32 random bytes, replace it in `hub.env` (or the Kubernetes Secret),
restart. All token-authenticated clients must be updated; OIDC sessions are
unaffected. There is no overlap window, so schedule it.

### Enrollment tokens and agent credentials — revoke and re-enrol

```console
$ cloop executor agents                  # enrolled agents + outstanding tokens
$ cloop executor revoke <token-id|agent-id>
$ cloop executor enroll --name edge-1 --ttl 15m
```

Revocation cascades from the enrollment record to the credential derived from it,
and the hub sends `bye` with `reconnect=false` so the agent stops rather than
retrying. Enrollment tokens expire on their own (15 min default, 24 h max);
**agent credentials do not expire** — revocation is the only way to end one.

On a device running the installed service, re-enrolling means replacing the
credential file rather than editing the unit:

```console
# on the device, as root
$ install -m 0600 /dev/null /var/lib/cloop-executor/enrollment
$ printf '%s\n' "$CLOOP_ENROLL_BUNDLE" > /var/lib/cloop-executor/enrollment
$ rm -f /var/lib/cloop-executor/agent.json      # drop the revoked identity
$ systemctl restart cloop-executor
```

The agent removes the enrollment file once it has redeemed the token, so an
empty `/var/lib/cloop-executor/enrollment` on a healthy device is expected, not
a fault. To remove the device entirely, `cloop executor agent install
--uninstall --purge` — idempotent, and it verifies afterwards that no unit,
credential or state directory survives.

### Sealing keys — online, resumable, no credential re-minting

Stored credentials are not encrypted under `CLOOP_SECRET_KEY` directly. Each row
gets its own random **data-encryption key** (DEK) which seals the payload; only
the DEK is sealed under a **key-encryption key** (KEK) derived from the
passphrase. Rotating therefore rewraps sixty bytes per row and never decrypts a
payload, which is what makes it safe to run against a serving hub.

Several KEKs can be openable at once. Rows move to the new one individually and
reads keep succeeding against whichever key each row still names, so there is no
window in which anything is unreadable.

```console
$ cloop hub key status                   # which key is sealing what
$ cloop hub key rotate --dry-run         # count what would move
$ cloop hub key rotate                   # mint a new KEK and rewrap onto it
$ cloop hub key list                     # keys, and whether each is still openable
```

`rotate` covers **both** populations of long-lived sealed material — brokered
secrets and session refresh tokens — because they share one registry. Enrollment
tokens and agent credentials are not covered and do not need to be: they are
stored as SHA-256 hashes, never sealed, so no key can be rotated out from under
them (see [enrollment tokens](#enrollment-tokens-and-agent-credentials--revoke-and-re-enrol)).

**Interruption is safe.** Ctrl-C, a restart, a SIGKILL mid-write — the row in
flight is transactional and everything else is untouched, because rotation
retires nothing and the old key stays openable. There is no cursor to corrupt:
the work remaining is defined as "every row not yet under the target key", so
resuming is just running it again.

```console
$ cloop hub key rotate --continue        # resume onto the current primary
```

**Concurrent writes are not lost.** Each rewrap is a compare-and-swap against
the exact ciphertext that was read. A credential re-minted, or a session
refreshed, while a rotation is running is left alone and counted as *skipped*;
run `--continue` once afterwards to sweep those up.

**Run one rotation at a time.** Two concurrent runs each promote their own key
and pull rows back and forth. cloop detects this — a row that keeps returning is
reported and the run exits incomplete rather than looping forever — but the work
is wasted. If you see `still not under ... after 5 attempts`, check for a second
`cloop hub key rotate`, then `--continue`.

A hub that is *serving* while you rotate needs no coordination: it re-reads the
current primary before every seal, so new material lands under the new key from
the moment it is promoted, and it adopts that key on first use.

#### Retiring the old key — a deliberate second step

Rotation never destroys a key. Retirement does, and it is irreversible: it
blanks the KEK's salt so the key cannot be derived from `CLOOP_SECRET_KEY`
again, at all. Anything still sealed under it is then unrecoverable, which is
why retirement **refuses** while any row references the key.

```console
$ cloop hub key status                   # must report zero unrotated rows
$ cloop hub key retire <old-key-id> --yes
```

After retirement, a read of material still naming that key fails loudly and
specifically — `sealing key retired`, naming the key and when — rather than as a
generic decryption error. That distinction is the point: it tells you to
re-mint the credential rather than to go hunting for a passphrase problem.

#### Changing `CLOOP_SECRET_KEY` itself

Rotating the KEK does **not** change the passphrase — every KEK is derived from
it. Changing the passphrase is still a re-mint, and cloop now refuses to paper
over it: a hub started with a passphrase that cannot derive its live keys fails
to start, naming them, rather than minting a fresh key and quietly forking the
registry.

If you must change the passphrase:

1. `cloop secret grants --all > grants.txt` — record what exists (never the values)
2. `cloop db backup` and copy the **old** `hub.env` somewhere safe
3. rotate the underlying credentials at their sources (GitHub, cluster, registry)
4. set the new `CLOOP_SECRET_KEY`, restart the hub
5. `cloop secret mint` each secret with its new value
6. `cloop secret grant` to reconstruct the grants from `grants.txt`
7. `cloop secret lease --project <p>` to confirm delivery

Because step 3 is required regardless, treat *passphrase* rotation as credential
rotation. For everything short of that — a scheduled key roll, a suspected key
exposure, an audit requirement — `cloop hub key rotate` is the procedure, and it
needs none of the above.

#### Upgrading a hub that predates envelope encryption

Migration `0019_envelope_encryption.sql` stamps every pre-existing row
`legacy` and adds the columns; it cannot re-encrypt anything, because SQL cannot
decrypt. Those rows keep opening under the old construction until the first
rotation converts them:

```console
$ cloop hub key status                   # shows N rows as "pre-envelope"
$ cloop hub key rotate                   # upgrades them, once, permanently
```

Nothing breaks if you never run it. But until you do, those rows are outside the
rotation guarantee, and `status` will keep saying so.

### Grants — rotate by expiry, not by procedure

Short TTLs mean grants rotate themselves. See
[choosing TTLs](../guides/secrets.md#choosing-ttls).

---

## Upgrade

Schema migrations live in `pkg/statedb/migrations/`, numbered from `0001_init.sql`,
are embedded in the binary, and are applied automatically by `statedb.Open()` on
every start. Each runs in a transaction and records itself in `schema_migrations`
— together with the version of the binary that applied it — so a crash
mid-migration rolls back cleanly and the next start retries.

**There are no down-migrations. Migration is roll-forward only** — which is why
step 1 below is not optional.

```console
$ cloop db backup                        # 1. NOT optional — the only way back
$ cloop migrate --dry-run                # 2. what would change
$ cloop version                          # 3. install the new binary
$ cloop migrate                          # 4. or just start the hub; Open() migrates
$ cloop db verify                        # 5.
$ cloop hub healthcheck --endpoint readyz
$ cloop audit-log verify
```

Rolling the container image:

```bash
docker pull ghcr.io/blechschmidt/cloop:<new>
docker stop hub && docker rm hub
docker run -d --name hub ... ghcr.io/blechschmidt/cloop:<new>
```

Helm:

```bash
helm upgrade cloop deploy/helm/cloop-hub --namespace cloop \
  --set image.tag=<new> --wait --timeout 5m
```

`--wait` returns only once the readiness probe passes, which means the PVC
mounted, the ConfigMap landed, and SQLite opened under `readOnlyRootFilesystem`
and `runAsNonRoot`. Pin images by **digest** in production — cloop does not
verify image signatures.

Enrolled agents reconnect on their own backoff (1 s → 2 min); they do not need
upgrading in lockstep, but check `cloop executor ls` afterwards. Confirm
`cloop executor list` still shows the expected backends and that
`executors.allow_host_process` is still `false` — a config merge that silently
re-enables host execution is the regression worth looking for after every
upgrade.

### Long-lived runs after an upgrade

An upgrade replaces the hub's binary; it does not replace the runs the hub
started. A hub restart deliberately keeps them alive (the unit uses
`KillMode=process`, and a restarted hub adopts the runs it finds), so a run in
auto-evolve, which never ends on its own, keeps executing the build it started
with for as long as it lives. On 2026-10-06 the run driving cloop's own
repository was 132 builds behind the hub serving it: "done means committed",
switched on for the project three days earlier, had never been enforced, and the
disk floor was inactive on a 98%-full disk.

**Seeing it.** Every run records its process and its build (version, commit,
sequence on main, the schema it embeds) in its project when it starts — the
run-owner record — and journals it in the run's `session_started` row. Whatever
reads the project compares that record with its own build:

- the Overview's status line and the Tasks tab's run bar say
  *Running build dev+g4e35bf6, 132 builds behind this hub* while the run lags;
- `GET /api/state` carries `run_build` (`build`, `reference`, `behind`,
  `comparable`, `live`, `adoptable`, `pid`, `executor`), the `run_owner` record
  itself, `follow_builds`, and a pending `adopt_request`;
- `cloop status` prints `Build:    running dev+g4e35bf6 (sequence 831 on main)
  (pid 4242), 132 builds behind this cloop`;
- `cloop hub doctor` warns `runs.build_lag` for every `cloop run` on the host
  that is behind the doctor's build, or that never recorded one.

A run started by a cloop from before this record existed shows no build at all;
doctor says so ("has not reported its build"). Restart it once — Stop, then
Start — and from then on it can move by itself.

**Moving a run without stopping it** (host-process runs only):

```bash
# once, from the dashboard: the run's Overview → "Adopt at next task boundary"
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "https://hub.example.com/api/run/adopt-build?project_idx=0"

# or for good: Overview → Active Options → Follow New Builds, or
cloop run --follow-builds          # stores the option with the project, then runs
```

The request is gated like Start (`run.start`, and the executor's audience) and
audited as `run.adopt_requested`; it names the run's process (pid, start time,
boot id), so a run started later never acts on it. The run acts at its next
safe point — after the task in flight has been settled and stored, and before
the next task or evolve round starts; a parallel run first lets its round drain
and dispatches nothing new meanwhile. There it insists that no child process is
alive, persists its state, and validates the binary at the path it was started
from (`/usr/local/bin/cloop-latest` on :8888): `<path> version --json` must
answer within ten seconds with a `sequence` strictly greater than the run's own
and a `schema` at least the project database's, and the new build must accept
the run's own command line (`<path> run … --help`). A request never moves a run
past the build of the hub that filed it, and Follow New Builds waits until the
deployed file has been in place for three minutes: the deploy health-checks the
new hub for half a minute and puts the old binary back if that fails, and a run
that had moved in that window would have migrated its database past what the
rolled-back hub can open. It then writes
`.cloop/run-handoff-<pid>.json` (run id, evolve iteration, the consecutive
failure and empty-evolve counters, its status and pause reason, the reason it
moved) and calls `execve` with the same argv and environment plus
`CLOOP_RUN_HANDOFF`.

To the hub nothing happened: the pid, the `(starttime, boot_id)` identity the
local driver checks, the hub's run claim and the live log's stdout pipe all
carry over. The new image journals `run_reexecuted` (old and new build, and
why), writes `run.reexecuted` to the project's audit trail, updates the
run-owner record (`reexecs`, `previous`), and continues the run — no new
`session_started`, no `--replan`, no `--retry-failed` reset, no `pre_plan` hook,
no re-applied command-line toggles.

**When it does not move.** Every refusal is a `run_adoption` row in the event
history, with the reason, and the run carries on on the build it has:

| Journal says | Meaning | What to do |
| --- | --- | --- |
| `… is at the same sequence as this run's build` / `still holds the build this run is executing` | Nothing newer was deployed at the path | Wait for the deploy; check `/var/lib/cloop-latest/commit` |
| `… builds older than this run's build` | The path holds a rollback | Adoption never moves a run backwards; restart the run if you mean to |
| `… carries no sequence` | An unstamped build (`go build`) | Deploy a build stamped by the deploy script or `scripts/build-release.sh` |
| `… embeds schema N, behind the project database at M` | The deployed build is older than the database | Deploy a build at least as new as the schema |
| `` `version --json` failed `` / `did not answer within 10s` (`attempt N of 3`) | A broken binary, or a host too loaded to answer | Tried again at the next boundaries, three times per deployed file |
| `not an ELF executable` / `not a regular file` / `writable by its group` / `belongs to uid` | Not an installed binary | Fix the deploy; the next file at the path is looked at afresh |
| `does not accept this run's command line` | The new build dropped or renamed a flag the run was started with | Restart the run without it |
| `newer than the hub that asked` | The path holds a build the hub is not running yet — a deploy in progress | Ask again once the hub runs it |
| `child processes are still running` | Something the run started has not exited | It retries at the next boundary (Follow New Builds) or refuses the request |
| `… executor, which keeps its own upgrade path` | A container or device run | Upgrade the device (Executors → Upgrade) or rebuild the image |

Check a move on the host itself: the pid in `cloop status` stays the same,
`/proc/<pid>/stat` field 22 (the start time) is unchanged, and
`readlink /proc/<pid>/exe` names the deployed file instead of `… (deleted)`.

---

## Rollback

**A newer schema cannot be opened by an older binary once the difference
matters**, and there are no down-migrations. This is enforced, not merely
advised: an older binary compares the database's recorded version against the
highest migration it embeds and, for every version it is missing, asks what that
migration did.

Each migration is classified when it is applied and the verdict is stored in
`schema_migrations.compat`. A migration that only *added* objects — new tables,
new non-unique indexes, new views — is `additive`: a binary that predates it has
no statement that can name them, so their presence changes nothing it does.

Appending a column counts as additive too, under conditions that are checked
rather than assumed: the statement must be `ADD COLUMN`, the column must carry a
`DEFAULT` or be nullable, and it must bring no constraint — no `UNIQUE`, no
`PRIMARY KEY`, no `REFERENCES`, no `CHECK`. What makes that safe is that no
query in `pkg/statedb` issues `SELECT *`; every read names its columns, so an
appended one is invisible to an older binary, and the default keeps the rows it
inserts legal. A column that is `NOT NULL` with no default is `breaking`,
because every older `INSERT` would fail on it.

Naming its columns keeps an older binary's reads and inserts off a new column,
but not a write that replaces a whole row, and builds before Task 20388 wrote
three tables that way: `plan_tasks` (every save emptied the table and inserted
the plan again), `ci_exchanges` (`INSERT OR REPLACE`) and `quota_counters`
(the gauge rows were deleted and inserted again). Each such write resets every
column the writing binary does not know, so a build one migration behind erased
that migration's column on its first save. A column appended to one of those
tables is therefore recorded `additive-columns`. Builds from Task 20388 on write
those rows in place and open the database; earlier builds have never heard of
the verdict, read it as unknown, and refuse — a refusal instead of an erasure.
Migrations 0001–0059 keep the verdicts they were recorded with: an older build
that predates one of their columns goes on erasing it until it is replaced.

A migration that altered, dropped or constrained something that already existed
is otherwise `breaking`. Anything unclassified, including rows written by a
build that predates this bookkeeping, and any verdict the reading build does not
know, counts as breaking.

A database whose extra migrations are all ones the binary can tolerate —
`additive`, and for a build from Task 20388 on `additive-columns` — opens
normally. Otherwise the binary refuses, naming both versions, the build that
moved the schema forward, and which migrations specifically are incompatible.
A build from before Task 20226 has no guard at all and opens any database; no
verdict can stop it, so do not run one against a database a newer build has
migrated.

```console
$ cloop ui
Error: statedb: database schema is newer than this binary: database is at schema
version 30 but this binary carries 29 (applied by cloop v0.4.0 as
0030_widget_policy.sql at 2026-05-02T09:14:22Z); … Incompatible:
0030_widget_policy.sql. …
```

The refusal happens before the hub binds a port or takes the control-plane
lease, so a rolled-back image fails its health check instead of serving from a
schema it half-understands. Every command goes through the same path, and
`cloop hub doctor` reports it as `storage.schema` without needing the hub to be
startable — run that first when a rollback will not come up.

Rollback is therefore *restore*, not *downgrade*:

1. stop the hub
2. install the previous binary or image tag
3. `cloop db restore <backup taken before the upgrade> --force`
4. `cloop db verify`
5. start; check `/readyz`, then `cloop audit-log verify`

### When the schemas are known-compatible

Purely additive gaps are handled automatically and need no intervention — see
above. The escape hatch is for the rest: a migration classified `breaking` that
you have read and judged harmless for your rollback, or one left unclassified by
a build too old to record a verdict. If you have checked the migrations between
the two versions and none of them touches what the older build uses,
`CLOOP_ALLOW_SCHEMA_DOWNGRADE=1` opens the database anyway:

```bash
CLOOP_ALLOW_SCHEMA_DOWNGRADE=1 cloop ui
```

This is an escape hatch for a rollback you have already reasoned about, not a
default. Do not use it to open a database whose extra migrations include one
recorded `additive-columns` with a build from before Task 20388: that build
does open it, and its first write to that table erases the new column.
`cloop hub doctor` reports the variable being set as its own finding —
`storage.schema_guard`, a warning on its own and a failure while a skew is
actually present — so an exemption left in a Deployment manifest does not
quietly outlive the incident that justified it. Unset it once the rollback is
over.

Everything between the backup and the rollback is lost — task state, audit rows,
grants minted in the window. If that window is unacceptable, export the audit
trail before upgrading:

```bash
cloop audit-log export --format jsonl --verify --output pre-upgrade-audit.jsonl
```

The `.pre-restore.<UTC>` file that restore leaves behind is your way back out of a
bad rollback. Do not clean it up until the rollback is confirmed good.

---

## Fleet operations

```console
$ cloop executor list                    # registered backends and what they isolate
$ cloop executor ls                      # health, in-flight work, last contact
$ cloop executor test container          # preflight: run `cloop version` inside it
```

`list` states the sandbox type per executor, including `hypervisor-backed` for
one configured with a Kata runtime. `test` is what proves it: on a Kata executor
it additionally checks that the runtime name is registered with the CLI and that
`/dev/kvm` opens, then boots a real workload — see
[the Kata guide](../guides/kata.md#verifying-it).

Taking a node out of service:

```console
$ cloop executor cordon edge-01 --reason "kernel patch"   # no new work; running work continues
$ cloop executor drain  edge-01                            # no new work; wait for zero in-flight
$ cloop executor uncordon edge-01                          # back to whatever the probes justify
```

`uncordon` does not optimistically mark the node ready — it returns it to the
state its probes justify.

If a node dies rather than draining, the supervisor does it for you: three missed
heartbeats (~45 s) mark it `unreachable` and in-flight sessions are re-placed on
surviving nodes exactly once. See
[failover](../architecture/executors.md#failover-task-20162).

```console
$ cloop executor reap container          # remove sandbox containers/Pods left by earlier runs
```

`reap` takes an executor ID — it acts on one backend, not the fleet. Since Task
20191 a hub reaps on its own at startup, so this is for cleaning up after a hub
that is *not* running, or for a runtime shared with one that never will be.

### Moving a device onto the edge channel

A hub that runs an unreleased build of `main` (the reference deployment's
`dev+g<commit>`) can hand its devices its own build, signed by CI, once a
device is on the [edge channel](../guides/edge-channel.md). Once per device,
on the device:

```console
# 1. cosign, which every build is verified with (a single static binary).
$ sudo install -m 0755 cosign-linux-amd64 /usr/local/bin/cosign

# 2a. A device whose cloop already knows the channel:
$ sudo cloop executor agent install --upgrade --channel edge

# 2b. One whose cloop predates it: fetch an edge build, verify it by hand, and
#     let it install itself — see the guide for the download and the cosign line.
$ sudo ./cloop executor agent install --upgrade --channel edge --to edge:<commit>
```

The first writes `20-update-channel.conf` beside the unit and installs the
remote-upgrade helper (`cloop-executor-upgrade.path` and `.service`); both
survive later upgrades, and only `--channel stable` / `--remote-upgrade=false`
on the device take them away. Check what the agent says about itself:

```console
$ journalctl -u cloop-executor -n 30 | grep -E 'updates:|firewall:|remote upgrade'
  firewall: nft(8) — CAP_NET_ADMIN held by the agent, never by its workloads
  updates: edge channel — releases, and signed builds of main
$ systemctl is-active cloop-executor-upgrade.path
active
```

An inactive path unit means a request would never be read; the agent refuses
upgrades and says so in its banner (`remote upgrade: unavailable: … is not active …`) until
`sudo systemctl enable --now cloop-executor-upgrade.path`.

Then, from the dashboard: Executors → the device's **Upgrade** → *this hub's
build (`<commit>`)*. The device files the request, the helper verifies and
installs the build, and the device reconnects on it; the row's build chip
follows. On the device, the helper's journal has the whole of it:

```console
$ journalctl -u cloop-executor-upgrade
```

When the dialog does not offer the hub's build it says why — an unpushed commit,
CI still running, CI or the edge workflow failed, the build pruned, a
protocol the build would lower, or a device already later on `main` than the
hub — and the
[guide's table](../guides/edge-channel.md#upgrading-from-the-dashboard) names the
remedy for each. To go back: `/usr/local/bin/cloop.prev` is the previous
binary, `--to <release> --force` installs a release verified, and
`--channel stable` takes the device off the channel. Moving a device back on
`main` takes that `--force` on the device: its installer refuses an earlier
build however the hub or its agent asks
([rollback protection](../guides/edge-channel.md#rollback-protection)), and the
refusal is a `refused:` line in `journalctl -u cloop-executor-upgrade`.

**The hub's deploy builds the local `main`.** If it deploys a commit before
it is pushed, the dialog says so ("the deploy built commit … which is not on
GitHub"), and the build is offered as soon as the push's CI run passes and
`edge.yml` publishes it, about half an hour later. A push of several commits
runs CI — and so publishes an edge build — for the newest one only.

### After a control-plane restart

A hub that is killed mid-run does not lose the workloads it dispatched: the
containers, Pods and edge-device processes keep running, and on the next start
each driver reattaches to its own from `executor_handles`. What is left over
after that — session rows nothing will close, workloads nothing can reattach to,
worktrees nothing will merge — is swept in the background, bounded at two
minutes, so a git prune and a runtime listing never delay the listener. See
[durable handle identity](../architecture/executors.md#durable-handle-identity-task-20191).

The sweep reports what it did through the hub's normal log, prefixed `ui:` under
`cloop ui` and `apiserver:` under `cloop serve`. The lines worth recognising:

```
executor: 3 in-flight session(s) reattached to a still-running workload
executor: closed 1 stale in-flight session(s) left by a previous control plane (drain would otherwise have waited on them forever)
executor container: garbage-collected 2 exited container(s) from a previous run: cloop-app-a1b2, cloop-app-c3d4
executor container: killed 1 container(s) still running from a previous control plane: cloop-app-e5f6
executor: pruned 2 leaked task worktree(s) in /srv/app: worktree gc: removed 2 worktree(s) and 0 branch(es); kept 5; 0 error(s)
```

**"reattached" is the good line.** Those runs survived the restart: their output
continues in the dashboard and their exit codes are still collected.

**An edge device's run is adopted when its agent dials back in** (Task 20382).
The sweep runs before any agent has reconnected, so it leaves a device's session
open rather than closing it as failed. When the agent reconnects, the process it
reaches adopts the run — `adopting a run from another hub member … reason="its
agent reconnected to this hub member"` — and takes over the run's secret lease,
one `took over the secret lease of an adopted run` line per lease. From then on
the run is that process's: it streams it, merges the device's result into the
project once, keeps the lease alive, releases it when the run ends, and closes
the session with how the run ended. A lease that lapsed while the hub was down —
down for longer than the lease had left, which the keepalive keeps between about
five and fifteen minutes — or whose grant was revoked meanwhile is scrubbed from
the device instead (`lease.revoke_sent` by `janitor`), and the run carries on
without those credentials. A run whose agent never comes back keeps its session
open for failover, and its lease until it lapses, when the leader's lease
janitor sweeps it.

**What the lease feeds comes back with it** (Task 20383). The run's git proxy
and Kubernetes monitor sessions are restored in the adopting process under the
ids and tokens the workload already holds, one line each:

```
ui: restored git session 3K2x… of lease lease_9f1c…, held until then by hub_7d0e…
ui: restored kube session qT8w… of lease lease_9f1c…, held until then by hub_7d0e…
```

and a `gitproxy.session_restored` / `kubeguard.session_restored` row. A GitHub App
token behind the git session is minted again at the scope recorded for it (an
allowed `secret.renew` row: *"re-minted at the scope recorded for it by the hub
process that took the lease over"*), and an App token the workload holds as a
file is renewed before its hour by the new process's keepalive. The run's egress
session is restored too, with its byte counters — the project's journal says
*"egress: proxy session … restored by the hub process that adopted this run"*.
A request the workload makes in the seconds before its agent reconnects waits up
to 60 seconds for this instead of failing.

A session that does not come back says why on its close row: a
`gitproxy.session_closed`, `kubeguard.session_closed` or `egress.close` whose
reason starts *"not restored by the hub process that adopted its run"* (its grant
was revoked or expired while the hub was down, its recorded scope is wider than
the grant or the proxy's policy now allow, its record names an upstream other
than the forge this hub's git proxy fronts, or this hub runs no such proxy), or
*"lapsed … while no hub process held it"*. A record naming another upstream was
not written by this hub: treat it as a sign the database was edited, and look at
who could write to it. The workload then gets a 401 (git,
kubectl) or a 407 (egress) from there on; stop and start the run to lease it
afresh. A line ending *"(will retry)"* is a restore that failed for a reason
that may pass — the database busy, GitHub unreachable for the App token — and is
retried every minute by the lease's keepalive (every 30 seconds for egress), and
at once by a request presenting the session. Count them with
`cloop_proxy_session_restores_total{kind,outcome}` (see
[metrics](metrics.md#sessions-restored-with-an-adopted-run)).

**A device workspace's pinned session comes back too** (Task 20390), when the
device keeps it for a push write-back (`executors.write_back: push`): the run's
owner row names its workspace lease, which the adopting process takes over —
one `took over the workspace lease of an adopted run` line — and the session is
restored like the lease's, with the same `restored git session …` line. Its
upstream is the project's own `origin` as the hub's checkout names it now, so a
record whose repository no longer matches is refused with *"it is pinned to …,
and the project's origin is … now"*. The device's write-back push, whenever it
comes, then lands, and the project's journal records it as a `write_back` row
naming the branch. A Pod's workspace session is not restored — see
[limits that remain](../architecture/git-proxy.md#limits-that-remain).

**A CI relay session is restored by the next call that presents it** (Task
20390), not by an adoption: no run or lease stands behind it. A hub stopped
gracefully writes a `ci.session.suspended` row per live session; the job's next
call to any hub process restores it, with a `ci.session.restored` row whose
`detail` names the process that held it and anything its rule narrowed. A
session whose rule was deleted, disabled or no longer admits its pipeline gets a
`ci.session.closed` row instead — *"not restored by the hub process that received
its next request: its rule is disabled"* — and the job a 401. A session killed
with its hub may have counted up to its last 15 seconds of spend short. The
**Live sessions** panel lists a session no process serves as *suspended*;
**Revoke** there ends it before its job calls again. A revocation, rule edit or
switch-off that ends a record another member serves — or one a member is
restoring at that moment — reaches that member at its next checkpoint, within
15 seconds; the API has answered by then. A **Revoke** answered `503` (*"its
record could not be closed"*) ended the session on the member that answered but
left its record open, so another process could still restore it: revoke it
again.

**Switching CI federation off is per hub instance** — the `cloop ui` port,
whose [overlay](../reference/configuration.md#two-dashboards-in-one-directory)
may set `ui.ci.enabled` — and each session's record names the instance that
served it. When an instance's configuration turns federation off:

- **The process serving it** ends its sessions: at once through Settings,
  which also tells the other members to re-read their own configuration, or
  within 15 seconds when the file is edited.
- **Its suspended records** end at once through Settings, and otherwise
  within a minute. The leader reads every instance's configuration the way
  that instance does, since the overlays live in the hub's directory, so
  this happens whether or not the instance is running. Before then, a
  restore refuses such a record (*"federation is switched off on the hub
  instance that served it (port …)"*).
- **An instance that keeps federation on** keeps its records.

So:

- **To stop every pipeline at once** in a cluster whose overlays differ,
  disable or delete the rules. That closes their records wherever they are
  held, and members drop the sessions within 15 seconds.
- **A quick off-and-on** ends only what was noticed while it was off. Every
  relay call is refused while it is off, whichever member receives it.
- **A record a live member took over but could not restore** stays until it
  lapses or its rule changes. It is restored only under its rule as the rule
  stands then.

**"killed N container(s) still running from a previous control plane" is the one
to read carefully.** It means a sandbox was *executing a harness* when it was
collected — work in progress was destroyed, not litter tidied away — and it is
deliberately worded differently from the "garbage-collected N exited" line so the
two are distinguishable in a log. It fires only for a container older than the
[grace period](../reference/configuration.md#container-sandbox) that carries this
executor's own labels and that no live handle claims, which after a healthy
restart should be nothing: rehydration adopts what it can, so anything reaped was
dispatched by a process with no handle store or one whose rows were lost. Seeing
it routinely means handle persistence is not working — check the startup log for
`handle persistence unavailable`, which names the reason and warns that workloads
dispatched by that process will not survive a restart.

`localprocess` is the driver that recovers least, and an operator will see it in
the run's own log rather than the hub's. A host workload that survived a restart
carries a `[cloop]` line saying its live output was lost with the pipe that
carried it, and that the process is still being watched; one whose pid was
recycled, or whose host rebooted, is reported `failed` with exit code `-1` and a
message naming which. That is honest rather than pessimistic — the exit status of
a process this hub was never the parent of genuinely cannot be collected, and
reporting `exited(0)` would mark failed work as done.

### A drain never finishes

`cloop executor drain <id>` (and the dashboard's drain button) waits for the
executor's in-flight session count to reach zero and gives up with
`ErrDrainTimeout`. Before Task 20191, a hub that restarted while a run was in
flight left a `running` row in `executor_sessions` that nothing would ever
close, so drain timed out on that executor *permanently* — the count never moved,
and no amount of waiting helped.

The startup sweep is the fix, so the first thing to try is a restart of the hub:
it closes rows whose executor no longer knows the handle. If drain still hangs
after that, the count is real and the sweep has deliberately left the rows alone
— `sessionOutcome` treats a driver that cannot answer (an unreachable cluster, a
device that has not dialled back in) as *live*, because closing a session whose
workload is actually running would let the scheduler re-place its task and put
two agents in one repository. Check the executor's health with `cloop executor
ls` and fix the reachability. `--force` stops *waiting* rather than failing — the
node stays draining, and the sessions it reports are still running and were not
touched.

### A task is quarantined as a suspected node killer

Two or more executors went unreachable while one task was running, so the
hub's failover failed the task and marked it (Task 20391): it will not run
again — not on the next dispatch, not under retry-failed — until somebody
resets it. Find them, with the nodes each went down under:

```bash
cloop executor list --inventory    # "Suspected node killers", per project
```

The task's details on the dashboard say the same, and the project's Event
History has a `failover` row for each lost node. Before releasing it, look at
why those nodes went down: a device's own journal (`journalctl -b -1` after a
reboot, the kernel's OOM and panic lines) usually names the culprit, and a task
that exhausted memory on two devices will on a third. Two unrelated node
failures can mark an innocent task, which is why the mark is a suspicion a
person clears rather than a verdict.

To run it again, reset it — from the task's status control on the dashboard,
or in the project's directory:

```bash
cloop task reset <id>
```

The reset deletes the mark and the losses behind it, so the task starts with
no evidence against it, and is recorded as `task.quarantine_release` with who
did it. A run that loses more nodes than `executors.failover.max_attempts`
allows stops being re-dispatched whether or not any task is marked; its
journal row names every node it lost.

### Pruning leaked worktrees by hand

Parallel task execution gives each task a git worktree under
`.cloop/worktrees/task-<id>` on a `cloop/task-<id>-<slug>` branch. A run killed
between creating the worktree and merging it leaks both. The hub collects the
*directories* on its next start, older than two hours and skipping any task it
believes is still running; it never touches a branch, because an unmerged one is
the only copy of that task's work.

```console
$ cloop worktree list                              # what is on disk, what git knows, and how old
$ cloop worktree prune --dry-run                   # the plan, including the branches it would keep
$ cloop worktree prune                             # remove directories older than 2h
$ cloop worktree prune --delete-branches           # …and merged cloop/task-* branches
```

Run these from inside the repository — both act on the current working
directory. `list` shows two shapes that are both leaks and both invisible to a
sweep that looks at only one source: a directory git no longer registers (`GIT`
`no`), and a registration whose directory is gone (`DIR` `no`).

`--min-age 0` disables the age guard and is the one flag here that can destroy
work: a live parallel run's worktrees are in that directory *right now*, and git
cannot restore what was never committed. Use it only when you have established
that nothing is running. `--delete-branches` is safe by comparison — it deletes
only branches already contained in the base branch (`--base`, defaulting to the
checked-out one), the check is enforced twice, and `git branch -d` refuses
unmerged work on its own authority. A branch reported as kept because it "is not
merged" is the API declining to destroy the only copy of a task's work; merge or
delete it yourself.

A non-zero exit from `prune` means some worktree could not be removed — a
permission error, a busy mount — and names it. The rest were still collected.

A worktree **locked** with the reason `cloop: kept for the task's next attempt` is
not a leak. Under [done means committed](../guides/done-means-committed.md), an
attempt that left its changes uncommitted (or stopped before it finished) keeps
its worktree for the next attempt at the task, which reopens it; neither `prune`
nor the startup sweep touches a locked worktree. If the task will never run
again, look at what it left (`git -C <path> status`), keep what you want, then
`git worktree unlock <path>` and prune.

---

## Incident playbooks

### Access emergencies

Three sequences you can paste. They exist as CLI commands rather than only as
dashboard actions because the situations that call for them are the ones where
a browser is the wrong tool or is not available: the listener is wedged, you are
on the host over SSH, or the account you need to contain is the one that would
be doing the containing.

Every mutation takes a required `--reason` and records it in the hash-chained
audit trail along with the OS user who ran it, so `cloop audit-log list` answers
"who did this, when, and why" without anybody reconstructing it from memory.
Read them back with:

```bash
cloop audit-log list --entity session --since 24h
cloop audit-log list --entity role_binding --since 24h
cloop audit-log list --entity quota --since 24h
```

#### An open hub is reachable from the network

`cloop hub doctor` fails `ui.exposure` with *a hub without sign-in listens on
\*:8080 (GET /api/projects … answered 200 without credentials)*. Anyone who can
reach that port can list the projects and start agent runs on the host, so
close it first and investigate second:

```bash
# 1. Close it, either way:
systemctl stop cloop-ui                                   # the unit serving that port
iptables -I INPUT -p tcp --dport 8080 ! -i lo -j DROP     # or keep it, loopback only
ip6tables -I INPUT -p tcp --dport 8080 ! -i lo -j DROP
# 2. What did it do while it was open? Projects, runs and tasks it was asked for:
cloop audit-log list --since 72h
# 3. Restart it with a build that defaults to loopback, or give it sign-in
#    (ui.oidc, or CLOOP_UI_TOKEN) before it listens on the network again.
```

The finding names the cause when it can: *this build would listen on
127.0.0.1:8080, so the process on the port is an older build or was started with
--listen*. A binary from before the loopback default binds every interface
whatever its configuration says, so only stopping it, or the firewall, closes it.

#### A session was stolen

Contain the session, then the credentials behind it. Order matters: revoking the
session first stops the active use while you work out what else the account
holds.

```bash
# 1. See what the account has open, and from where. The IP column is usually
#    what tells a stolen cookie from the user's own second browser.
cloop hub session list --identity alice@example.com

# 2. End one session, or all of theirs.
cloop hub session revoke 3f9c1e7a2b5d48c0 --reason "reported stolen laptop, INC-4412"
cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"

# 3. Sessions are not the only credential. Revoke any API token the account holds.
cloop hub token list
cloop hub token revoke <token-id>

# 4. If the account itself is suspect rather than just one cookie, demote it too
#    — see "A compromised admin" below.
```

```console
$ cloop hub session list --identity alice@example.com
ID                IDENTITY           IP             IDLE  EXPIRES            IDP CHECKED
3f9c1e7a2b5d48c0  alice@example.com  198.51.100.24  3s    2026-09-14 23:49Z  never
a1d4f80b6c2e93aa  alice@example.com  203.0.113.9    17m   2026-09-14 23:49Z  never

$ cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"
Revoked 2 session(s).
  3f9c1e7a2b5d48c0  alice@example.com
  a1d4f80b6c2e93aa  alice@example.com

A running hub may still honour these for up to 30s (its session cache).
API tokens are a separate credential — see `cloop hub token list`.
```

**The 30 seconds are real.** A running hub serves sessions from a per-process
cache with that TTL, which is the same bound it already accepts between
replicas. "I revoked it and they were still in" for a few seconds is this, not a
failure. If you need the window closed to zero, stop the hub.

This command reads and writes the session table directly and takes no
control-plane lease, which is deliberate: the case it exists for is a hub whose
listener is wedged, and that hub is still holding its lease.

#### A tenant is running away

One identity is consuming the shared budget, executor slots, or project count.
Cap it now and work out why afterwards.

```bash
# 1. What is this identity actually consuming?
cloop hub quota list

# 2. Cap it. The override is sparse — setting one ceiling leaves every other
#    one exactly as it was, inherited or overridden.
cloop hub quota set alice@example.com \
  --limit daily_cost_usd=5 \
  --limit max_concurrent_tasks=2 \
  --reason "runaway plan INC-4413"

# 3. Stop what is already running. A daily budget applied to a live hub does
#    end the run, but only once the spend catches up with it; the others
#    (max_concurrent_tasks, max_projects) bound the next request and nothing else.
cloop hub session revoke --identity alice@example.com --reason "runaway plan INC-4413"

# 4. Afterwards: drop one ceiling back to configured policy, or all of them.
cloop hub quota set alice@example.com --unset max_concurrent_tasks --reason "tasks back to policy"
cloop hub quota clear alice@example.com --reason "INC-4413 closed"
```

```console
$ cloop hub quota set alice@example.com --limit daily_cost_usd=5 --limit max_concurrent_tasks=2 --reason "runaway plan INC-4413"
Quota override for alice@example.com:
  max_concurrent_tasks         2
  daily_cost_usd               5

Takes effect when the hub next starts — it loads overrides once. Start it now,
or apply the same change through the Quotas panel on a running hub.

$ cloop hub quota list
IDENTITY           RESOURCE              OVERRIDE  USED  UPDATED BY
alice@example.com  max_concurrent_tasks  2         -     cli:root
alice@example.com  daily_cost_usd        5         -     cli:root
```

**This one refuses while a hub is running**, and points at the REST API:

```console
$ cloop hub quota set alice@example.com --limit daily_cost_usd=5 --reason "runaway plan"
Error: a hub is running here and holds the control-plane lease: hub-1 (cloop-0 pid 812)

This command writes state that hub loaded into memory at startup, so a
write now would neither take effect nor survive its next edit. Use PUT
/api/quotas/{identity} or the Quotas panel while it is running, or stop it first.
```

That is not a limitation to work around. The enforcer reads overrides once at
startup, so a write behind a live hub would be invisible to it *and* would be
overwritten by the next edit made from the panel. Use the Quotas panel, or:

```bash
curl -X PUT https://hub.example.com/api/quotas/alice@example.com \
  -H "Authorization: Bearer $CLOOP_PAT" \
  -H 'Content-Type: application/json' \
  -d '{"limits":{"daily_cost_usd":5,"max_concurrent_tasks":2}}'
```

A `daily_cost_usd` or `daily_token_budget` set this way does stop the run that
provoked it. The hub books each project's cost rows into the enforcer every 30
seconds, so the run ends at the first task boundary after the budget goes, with
`quota.spend_refused` in the audit trail naming the identity, the limit and the
usage. The other ceilings only bound the next request.

*How much* an identity is over is `cloop hub quota list`; *where it went* is
`GET /api/cost/identities?window=today` across the fleet, or `cloop cost report
--by-identity` inside one project. See
[per-identity attribution](../security/model.md#who-spent-it-per-identity-attribution).

#### Somebody leaves

**One command.** Disabling an account at the identity provider does not, on its
own, sever anything this hub has already issued. Seven surfaces outlive it:

| Surface | What survives an IdP disablement |
| --- | --- |
| Sessions | Until the absolute TTL — the refresh grant proves the grant is alive, not that the person still works here |
| API tokens | Until `ExpiresAt`. The owner binding was never consulted on departure |
| Glasses links | Same rows, same problem — up to 30 days |
| Deny binding | Does not exist until somebody writes it |
| Secret leases | Real credentials, materialised inside a running sandbox |
| Running tasks | Still executing, in their name |
| Project memberships | Other people's projects shared with them by name — until a maintainer removes them |

`cloop hub user offboard` severs all seven, and reports an eighth — the projects
they own — without touching it.

```bash
# 1. Look first. Nothing is changed, and the set printed is exactly the set
#    the write acts on.
cloop hub user offboard alice@example.com --dry-run

# 2. Do it.
cloop hub user offboard alice@example.com --reason "left the company, HR-882"
```

Sessions, API tokens, glasses links, project memberships and the deny binding
are written in **one transaction**: either the person is out of all five or
nothing changed. There is
no half-offboarded state to discover a month later. Leases and running tasks
cannot join that transaction — they are broker memory and other databases — so
they are applied after it, and any failure is reported rather than rolled back
over a severing that already succeeded. A partial run exits non-zero.

**Give an email or a subject; either resolves to both.** The surfaces are keyed
inconsistently — a session carries an email, a token's owner may carry only a
subject — so the command expands what you type to every identifier that turns
out to address the same person. Matching literally on the input is how a
departed user's PAT keeps working.

**Projects are reported, never deleted.** They usually hold the team's work.
The command lists them and writes a `user.offboard_project` audit event so the
reassignment is on somebody's record; `cloop workspace` is how you hand them
over.

The trail carries one event per surface touched, all under entity type `user`
and keyed by the identity, so the whole operation greps as one unit:

```bash
cloop hub audit --entity-type user --entity-id alice@example.com
```

The same operation is in the dashboard under **Secrets → Offboard a user**,
gated on `user.manage`. It previews before it writes, for the same reason the
CLI does. It refuses to offboard the identity making the request — that would
revoke the session issuing it and deny the account that must undo it; use the
CLI if that is really what you want.

> A running hub may keep honouring a revoked session for up to 30 seconds (its
> session cache). Tokens and deny bindings take effect immediately.

#### An admin is compromised

This is the one that had no answer before. Admin status comes from
`oidc.admin_emails` and `oidc.role_mappings`, which are read at startup — so
demoting somebody used to mean editing config and redeploying, with whoever
holds the deployment pipeline in the loop.

`cloop hub role revoke` writes a **deny binding** into the control-plane
database instead. It outranks every other binding at every specificity,
including the global admin binding `oidc.admin_emails` produces, and a running
hub picks it up within ten seconds without a restart.

```bash
# 1. Confirm where their authority comes from. This shows both layers: the
#    runtime bindings and the configured ones they override.
cloop hub role list --identity alice@example.com

# 2. Demote. This works while the hub is running.
cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"

# 3. A deny stops them acting. It does not end sessions or revoke tokens.
#    `cloop hub user offboard` does all three in one transaction, and is the
#    right tool unless you specifically want to demote without ending sessions
#    (e.g. containing an account you are still watching).
cloop hub session revoke --identity alice@example.com --reason "credential compromise INC-4412"
cloop hub token list        # then revoke anything the account holds
cloop hub token revoke <token-id>

# 4. Rotate anything they could have read: cloop hub key rotate, plus the
#    credentials behind any grant they could reach.

# 5. When the investigation closes, remove the binding by id. Deleting a deny
#    restores whatever remains in force — usually the configured policy, which
#    for an admin_emails entry means restoring admin. Do it deliberately, and
#    check `role list --identity` first: if a runtime grant for the same scope
#    is also stored, that grant takes over instead of the configured policy.
cloop hub role delete rb_e1be642bd28f --reason "investigation closed, account clean"
```

```console
$ cloop hub role revoke email alice@example.com --reason "credential compromise INC-4412"
DENIED email=alice@example.com (everywhere)
  binding  rb_e1be642bd28f
  This outranks every other binding, including oidc.admin_emails.
  Undo with `cloop hub role delete rb_e1be642bd28f`.

A deny stops them acting; it does not end their sessions or revoke their
tokens. For a compromise, also run:
  cloop hub session revoke --identity alice@example.com --reason "..."
  cloop hub token list   # then revoke anything they hold

A running hub picks this up within 10s. No restart needed.

$ cloop hub role list --identity alice@example.com
Runtime bindings (this database)
  ID               EFFECT  CLAIM  VALUE              ROLE  SCOPE     BY        REASON
  rb_e1be642bd28f  deny    email  alice@example.com  -     (global)  cli:root  credential compromise INC-4412

Configured bindings (.cloop/config.yaml)
  SOURCE        CLAIM  VALUE              ROLE   SCOPE
  admin_emails  email  alice@example.com  admin  (global)

alice@example.com is DENIED by rb_e1be642bd28f (everywhere) — every request resolves to no permissions.
```

**How long containment takes.** Three windows, and they are additive in the
worst case:

| | Bound | Why |
|---|---|---|
| REST and page loads | 10s | the binding TTL — bindings are re-read from the database on that interval |
| Open WebSocket or SSE stream | +30s | the writer loop re-checks the deny on its keepalive tick and closes the connection |
| Revoked session | 30s | the hub's per-process session cache |

So a demoted account stops being able to *act* within about ten seconds and
stops *receiving* within about forty. If you need both at zero, stop the hub —
which is also what you would do if you suspected the process itself.

**Precedence, in full.** Two rules, and nothing else:

1. **Deny wins.** An applicable deny binding denies outright, whatever else
   matches and at whatever specificity.
2. **The database overrides config.** If any runtime binding applies, the
   configured bindings are not consulted at all.

Both are needed for step 2 above to work: rank a deny against a tier-0 admin
binding and it loses; consult config after a runtime match and the admin binding
comes back.

**Scope it when you mean to.** With neither flag the deny is global. With
`--project` it withdraws authority on one project and leaves the rest intact:

```bash
cloop hub role revoke email contractor@example.com --project payments --reason "scope reduction"
```

**Other claims work too**, which matters when the provider releases no email:

```bash
cloop hub role revoke sub 8f14e45fce      --reason "offboarded, IdP entry not yet removed"
cloop hub role revoke group contractors   --reason "vendor breach, containing the whole group"
```

`cloop hub role grant` is the same mechanism in the other direction — a runtime
grant overrides the configured bindings, so it is also how you narrow somebody
(`--role viewer`) or widen them for one project, without a redeploy. It does not
beat a deny, and it is *not* the way to undo one: granting over a live deny
stores an inert row. The command says so, and `role delete` is the undo.

A binding cannot be narrowed to a project and an executor at the same time. No
request carries both — an executor action is a fleet action and deliberately
resolves with no project — so such a binding would match nothing. The command
refuses it rather than storing a deny that withdraws nothing.

Runtime bindings are policy that no reviewed file records, so a hub that has any
says so at startup:

```
RBAC: 2 role mapping(s), default role "none", plus 1 runtime binding(s) (1 deny) — see `cloop hub role list`
```

Treat that line as a reminder to clean up: a deny from a closed incident that
nobody removed is an account somebody thinks still works.

---

**A credential leaked.**
`cloop secret revoke <grant-id>` — then remember that material already
materialised survives up to 15 minutes, so stop the affected runs too. Rotate the
credential at its source. `cloop audit-log list --entity secret --since 7d` shows
who granted what and when. For egress, `cloop egress revoke` is immediate: live
sessions are torn down mid-tunnel — at once when revoked in the dashboard of the
hub holding them, and within a minute from the CLI or another hub member, which
the holding hub learns of by re-reading the grant every minute of a run.

**An executor is compromised.**
`cloop executor revoke <agent-id>` (cascades to the credential; the agent is told
not to reconnect), then `cloop executor cordon` any peer that shared its grants.
Audit-log `--entity executor` for what it was given. Assume every secret ever
leased to it is disclosed and rotate accordingly.

**`cloop audit-log verify` exits 2.**
Do not vacuum or maintain — that rewrites pages. Snapshot the file, `cloop db
verify` to separate corruption from tampering, and compare against your last
off-box export to find where the histories diverge.

**`/readyz` fails but `/healthz` passes.**
Read the `check` field first — it names which gate failed.

`"check": "sqlite"` is storage. Check the volume is mounted and writable, then
`cloop db verify`. Under Kubernetes, check the PVC is bound and that no second
replica is mounting it — SQLite is `ReadWriteOnce` and the chart pins
`replicaCount: 1` for that reason.

`"check": "identity"` means the hub has never resolved its OIDC issuer, so
nobody can sign in. The `error` field names the URL that was contacted and the
HTTP status it returned, and `remediation` says what to change. Run
`cloop hub doctor` from the same host for the full diagnosis — it performs the
same two round trips and prints the resolved authorization, token and JWKS
endpoints, which is the fastest way to tell a wrong realm path from a
certificate the hub does not trust. The gate clears on its own once the
provider answers, including via an ordinary sign-in; no restart is needed.

**Users keep seeing "Your sign-in needs renewing".**
The dashboard tried to re-assert their claims from the browser, because the hub
holds no refresh token for the session, and the provider would not answer
without showing the user something. Clicking **Sign in** fixes it for one
`max_claim_age_minutes` window. If it recurs across users,
`cloop_oidc_renewal_total{outcome="interaction_required"}` will be climbing:
their browsers keep the provider's cookies out of frames (Safari, Firefox, a
hardened Chrome), or the provider refuses to be framed at all — the latter never
reaches the hub and shows only in the browser console as a framing violation.
Either way the remedy is the same: set `CLOOP_SECRET_KEY` and add
`offline_access` to `ui.oidc.scopes`, so the hub re-asserts the claims itself and
the browser never has to. In `cloop hub session list`, a session that stays at
`never` under IDP CHECKED is one the hub has nothing to re-check with. See
[Silent renewal from the browser](../security/model.md#silent-renewal-from-the-browser).

**The hub exits with "another cloop hub controls this state and cannot share it".**
Not a bug — a hub that is not a cluster member is serving this control plane:
one from before clustering, or one running with `ui.cluster.exclusive`. The new
one refused rather than diverging from it. See
[when a hub refuses to start](#when-a-hub-refuses-to-start).

**A member logs "stepped down: leadership was lost".**
It could not renew the lease for a full TTL — usually a long pause (a suspended
node, a stalled volume) — and another member took over the leader's duties. It
keeps serving as a member, which is correct: the duties moved, the dashboard did
not. If it happens repeatedly, look for what is stalling that process.

**A hub started with `ui.cluster.exclusive` logs "standing down" and exits.**
The same loss of the lease, under the pre-cluster rule that setting restores:
past that point another hub owns the state, so this one stops rather than
serving beside it. Find the other with `cloop hub lease status`.

`"check": "executors"` means the hub has nothing to dispatch to: strict mode is
on and no isolating executor registered. The `remediation` field says what to
do. The usual causes, in order of frequency:

- the config enables no isolating backend at all — set
  `executors.container.enabled` or `executors.kubernetes.enabled`, or enroll an
  edge device;
- one is enabled but could not be *built* — no container runtime on the hub
  host, or no kubeconfig grant. `GET /api/executors` carries a `reconciliation`
  block with a per-driver `status` and `remediation`, and the startup log has
  the same line;
- the hub is running in a distroless image (as the chart's is) with
  `executors.container.enabled: true`. There is no container runtime inside
  that image; use the Kubernetes backend, which is what
  `executor.kubernetes.enabled` in `values.yaml` configures.

Do **not** set `allow_host_process: true` to clear this. That does make the
probe pass, by removing the isolation boundary the gate exists to enforce.

**A sandbox cannot reach something it should.**
Work down the layers; each step rules one out.

1. **Ask the filter.** `--check` reports the verdict and the rule that decided
   it, and puts the verdict in the exit status (0 allow, 1 drop) so it composes
   into a script. Give it the *address*, not a name — a packet filter matches
   addresses:

   ```console
   $ cloop egress firewall --cidrs 10.8.0.0/24 --ports 6443 --check 10.8.0.5:22
   DROP  10.8.0.5 10.8.0.5:22/tcp — private (RFC1918/ULA)
   ```

   Reading the reason matters: `private (RFC1918/ULA)` means the address was
   inside the granted range but the *port* was not, so the waiver did not apply
   and the block set caught it. `default deny` means nothing matched at all.
   Use the same flags the executor is configured with, or `--grant <id>` to
   compile a stored grant. See
   [`cloop egress firewall`](../reference/commands.md#cloop-egress-firewall).

2. **Check that DNS is allowed — this is the most common cause by a wide
   margin.** A `filtered` policy with no `resolvers` drops UDP/53 along with
   everything else it does not name, and the symptom is not "DNS is denied", it
   is every connection failing at name resolution, which reads exactly like a
   network outage. The compiler warns about it at compile time:

   ```console
   $ cloop egress firewall --internet --ports 443 --format rules | grep -m1 resolver
   warning: no resolver is allowed, so DNS will fail: name lookups leave the sandbox on UDP/53 and this policy drops them. Pass the sandbox's resolvers, or use the broker, which resolves on its behalf.
   ```

   The fix is to name the sandbox's resolvers in
   `executors.container.egress_filter.resolvers`, or to route the sandbox
   through the broker, which resolves on its behalf. On Kubernetes, check that
   `allow_cluster_dns` has not been set to `false`. Resolvers are opened on TCP
   as well as UDP, because a truncated answer retries over TCP and a
   UDP-only resolver fails on large responses in a way that looks like a
   different bug.

3. **Look at the counters on the host.** Every rule carries one, so the ruleset
   shows what is actually being dropped rather than what should be:

   ```bash
   nft list table inet cloop_sbx_<executor-id>
   ```

   The table name is `cloop_sbx_` plus the executor id lower-cased, with every
   character outside `[a-z0-9]` replaced by `_`. A non-zero counter on a `drop`
   rule names the destination range and the reason; a zero counter on the
   `default deny` line means the traffic never arrived, which points upstream —
   at routing, at the image, or at the workload not trying.

   There is **no table for an `internal: true` filter**, and that is not a
   fault: that form installs no rules at all, because the runtime puts no route
   off the bridge in the first place. If `nft list table` says the table does
   not exist, check which form the executor is configured with before
   concluding the filter failed to install — and note that a failed install
   fails the `Start`, so a running sandbox is never one whose rules went
   missing.

4. **Re-run preflight.** `cloop executor test <executor-id>` is the command
   that surfaces the driver's `egress` finding — what the filter will enforce,
   or that it is not filtering at all — plus a separate `egress-scope` finding
   for anything the filter is wider than its grant. Exit 2 means preflight
   found a fatal problem and no workload was attempted; the usual ones are
   `nft(8)` missing or the control plane lacking `CAP_NET_ADMIN`, both `fail`,
   both with the fix in the message, and both avoidable by switching the filter
   to `internal: true`, which needs neither. `cloop hub doctor` does not repeat
   these findings — its `executors` group reports reconciliation, the
   strict-mode gate and a liveness probe.

5. **On Kubernetes, confirm the CNI implements NetworkPolicy.** cloop creates
   the object and the API server stores it whether or not anything enforces it,
   so a cluster running flannel looks identical to a working one from the hub's
   side — and the failure is the opposite of this playbook's: traffic that
   should be *blocked* is not. `kubectl get netpol -n <ns> -o yaml` shows what
   was created; only the CNI's own documentation says whether it is honoured.

If the destination is one the sandbox should reach through the **proxy** rather
than directly, this is the wrong tool: `cloop egress test <url>` asks the
layer-7 question, and a host allowlist is only ever enforced there.

**A run's requests through the egress proxy fail.**
Read the project's Event History for `egress` rows first: every run whose project
holds a grant gets either a "proxy session … issued … reaches the proxy at X" row
or a row saying why it got none — the grant revoked or expired, no proxy on the
hub, no network for the run, or no route from its executor (a loopback-bound
proxy and a container, an advertised address a device cannot reach, an agent
older than v18 behind a device firewall). `cloop hub doctor` reports where each
running hub's proxy listens (`egress.hosted`). The audit trail has the rest:
`egress.redeem`, one `egress.connect` / `egress.request` per verdict with the
host, port and reason, `egress.renew`, and `egress.close` with the session's
byte counts. A harness that honours `HTTPS_PROXY` sends its model API traffic
through the proxy too, so a grant that omits the model API's host is the usual
cause of a harness that cannot reach its model.

**"database is locked".**
WAL and `busy_timeout` are already configured, so this points at a second writer.
Check for a stray `cloop` process on the same `.cloop` directory, or a shared
volume.

**A run stopped: "run progress could not be saved".**
The project database refused a write the run could not do without — a task's
outcome, a pause, a plan change — so the run stopped rather than report work
the database does not hold. The badge, `cloop status` and the Event History
name the write that failed and the database's own error:

```
Status:   paused
Reason:   could not save task #12's completion (status done): database or disk is full
```

The usual causes are a full disk, a read-only mount or file permissions, a
lock another process held past `busy_timeout`, and a damaged task row (see "A
task row that will not load" above). Fix that first; `cloop db verify` checks
the file itself. Then start the run again: the tasks the stopped run left in
progress are recovered the usual way — an outcome its agent had already
reported is adopted rather than run again, and anything else is re-queued.

When the database took nothing at all, not even the stop, the run's exit
status is 74 and its last lines of output say what failed. The hub reads that
status, records the same pause on the run's behalf, and journals it, so the
dashboard reads the same either way — provided the hub itself can write.

**Nothing will schedule.**
Read the placement error: it names the constraint and lists per-candidate
rejections. `host_policy` means strict mode refused the only available executor —
correct behaviour, wrong fleet. Bind the project to an isolated executor or
enable the container backend; do **not** set `allow_host_process: true` to make
the message go away.

**A project shows "running" but nothing is running.**
This resolves itself. A run that is killed rather than stopped — the kernel's
OOM killer, a `SIGKILL`, a host reboot — never writes a terminal status, and the
hub reconciles that within a few seconds: the project returns to `paused`, each
task the run left in progress is either adopted (its agent had finished and said
so, so the outcome is taken rather than the work redone) or re-queued, and the
event journal records why. Look there first: the entry names the cause,
and an out-of-memory kill says so explicitly along with the remedy (give the
executor more memory, or make the task hold less at once). Repeated OOM entries
for the same project are a sizing problem, not a cloop problem.

If it does *not* resolve, the hub is telling you it refused to. Check the server
log for `stale-run recovery: skipped, state points at another directory` — that
is a project whose `.cloop` was copied or moved from somewhere else, so its
persisted `WorkDir` names its old home and writing the repair would land in the
original project's database. Fix the state file rather than the symptom.

**Restarting the hub does not stop the runs it started.**
This is deliberate, and it is why the nightly rebuild of `cloop-latest` does not
interrupt work in progress. Runs are orphaned rather than killed
(`KillMode=process` on both hub units) and they are built to outlive the hub: a
run whose output pipe breaks keeps working and still records its outcome, so
losing the hub costs the live-log stream and nothing else. Progress keeps landing
in `state.db`, so the task list stays current even while the log panel is empty;
streaming resumes with the *next* run, not the one that was in flight. A run on
an edge device is better off: the restarted hub adopts it when its agent dials
back in, and streams, merges and settles it as the stopped one would have — see
[after a control-plane restart](#after-a-control-plane-restart).

Before this, such a run died — not of the kill, but of its own next log line,
because Go makes `SIGPIPE` fatal on file descriptors 1 and 2. That committed the
work and lost the outcome, which was the most common way a project came to be
stuck showing "running" at all. If you want a run to stop, stop it: the Stop
button, or `POST /api/projects/{idx}/stop`.

---

## See also

- [Executor architecture](../architecture/executors.md) — health, cordon, failover
- [Security model](../security/model.md) — what the boundaries authenticate with
- [Threat model](../security/threat-model.md) — deployment-level threats
- [Secret and egress grants](../guides/secrets.md) — grant and revoke procedures
- [Kata Containers](../guides/kata.md) — VM-isolated sandboxes: setup and verification
- `deploy/README.md` — image, compose stack and Helm chart specifics
