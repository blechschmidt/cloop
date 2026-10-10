# Hub cluster

How several `cloop ui` processes serve one control plane, what they share,
what each keeps to itself, and what happens when one of them goes away.

Every `cloop ui` joins the control plane at its working directory as a
**member**. One member is fine and is what a default install runs. Start more
in the same directory — or raise `replicaCount` in the Helm chart — and they
serve the same projects, runs, executors, users and secrets behind one load
balancer, with no session stickiness:

- a request can land on any member, and a member forwards to another the few
  requests only that one can answer;
- a dashboard attached to any member sees live output, run state and presence
  from all of them;
- when a member stops — crashed, killed, or replaced by an upgrade — the others
  pick up its runs, its edge agents and its duties.

What replicas buy is availability and upgrades without downtime, plus request,
WebSocket and agent connections spread over several processes. What they do not
buy is a second machine: the control plane is one SQLite database, and every
member has to reach it through [one kernel](#what-a-cluster-requires). Capacity
to *run* work scales out through [executors](executors.md) instead, which is
where the work was never meant to leave anyway.

- [What a cluster requires](#what-a-cluster-requires)
- [Running one](#running-one)
- [What the members share](#what-the-members-share)
- [Runs, agents and failover](#runs-agents-and-failover)
- [The peer channel](#the-peer-channel)
- [Configuration](#configuration)
- [Operating it](#operating-it)
- [Limits](#limits)
- [How it is tested](#how-it-is-tested)

---

## What a cluster requires

**One database file, opened by every member through the same kernel.** Members
on one machine, or containers and Pods on one node sharing one volume. SQLite's
write-ahead log keeps its index in shared memory, so it does not work over a
network filesystem, and the event bus's sequence-number cursor relies on SQLite
admitting one writer at a time. A control plane spread over several machines
would need a network database; this is not that.

Nothing else is assumed. Members need not share a pid namespace, a process
table or a loopback interface — containers on one node have none of those in
common — because every question one member asks about another is answered from
the database or over the [peer channel](#the-peer-channel).

**Every member must be able to reach every other** at the address it
advertises. On one machine that is loopback and the member's own port, the
default. Anywhere else, see [configuration](#configuration).

**Every member must see the same project registry.** The list of registered
projects lives in `$HOME/.cloop/projects.json` (or under `CLOOP_HOME`), not in
the database, so members started with different homes would each list a
different set of projects. The Helm chart puts `HOME` on the shared volume for
this reason.

---

## Running one

### On one machine

```bash
cd /srv/cloop
cloop ui --port 8080 &
cloop ui --port 8081 &
```

Put any load balancer in front of the two. It needs no stickiness and no
WebSocket affinity — only a health check (`/healthz` for liveness, `/readyz` to
take a member out of rotation). Each member advertises
`http://127.0.0.1:<port>` to the others unless told otherwise — or, when it
listens on one interface's address (`--listen`, `ui.listen`), that address.
Members without sign-in listen on `127.0.0.1` only, so on one machine they
still reach each other; on several, they need sign-in to listen on the
network at all ([Web UI](../reference/configuration.md#web-ui-cloop-ui)).

Per-member settings, if a member needs any, go in its instance overlay
(`.cloop/config.ui-<port>.yaml`); `.cloop/config.yaml` is shared by all of them.
Each member enforces its own merged view of the
[hub-scope keys](../reference/configuration.md#two-dashboards-in-one-directory),
so a policy written into one member's overlay (`executors.allow_host_process`,
`sandbox.image_policy`, `executors.git_proxy`) binds that member only. The load
balancer would then decide per request which policy applies. Put policy that
every member must enforce in `config.yaml`.

### In containers on one host

Mount one volume into every container as the state directory, and tell each
container how the others reach it: `CLOOP_CLUSTER_ADVERTISE_HOST` with the
container's address (cloop adds the scheme and port), or the whole URL in
`CLOOP_CLUSTER_ADVERTISE_URL`. A shared `hostname:` between containers is
harmless — liveness is keyed to the pid namespace as well as the host.

### On Kubernetes

Raise `replicaCount` in the [Helm chart](../../deploy/README.md#replicas). The
chart pins every replica to the node the ReadWriteOnce volume is attached to,
sets `CLOOP_CLUSTER_ADVERTISE_HOST` to each Pod's IP, switches the Deployment
to a rolling update that starts a replacement before a member leaves, and
refuses to render replicas without persistence.

### Checking it

```console
$ cloop hub cluster status
Hub cluster
  /srv/cloop/.cloop/state.db

  hub_d74093a016f4198a7ec530075841bd4f  serving
      host hub-1 pid 2476196, listening *:8080, reachable at http://127.0.0.1:8080
      version v0.9.0, started 2026-09-28T22:07:33Z
  hub_2fe01f4e6fca955c89bf53189ef133df leader  serving
      host hub-1 pid 2476198, listening *:8081, reachable at http://127.0.0.1:8081
      version v0.9.0, started 2026-09-28T22:07:33Z

  2 member(s) serving
```

It reads the database directly, so it answers with every member down — which
is when "who was serving, and who led" matters most — and it lists what each
member holds that the others forward to it. `--json` for scripts.
`GET /api/cluster` (permission `executor.manage`) is the same view from a
running member, with that member's bus counters. Every response carries
`X-Cloop-Served-By: <member>`, naming the member that answered it.

---

## What the members share

Four things, all through the database they already share
([`pkg/hubcluster`](../../pkg/hubcluster/hubcluster.go), tables from
`migrations/0052_hub_cluster.sql`).

### Membership

Each member keeps a row in `hub_members` and renews it every 5 seconds. A
member that stops renewing for 20 seconds is dead; one that leaves gracefully
says so and is dead at once. A member on the same machine and in the same pid
namespace is also probed by pid, so the common crash — a supervisor restarting
a killed process within seconds — is noticed within a heartbeat rather than a
TTL. A pid from another namespace is never probed: it would name nothing, or
the wrong process.

A member also announces its arrival and its departure on the [bus](#events),
so the others learn of either within a poll rather than at their next
heartbeat. That matters most for arrivals: a member that believes it is alone
publishes nothing, and a newcomer it has not noticed would miss the start of
every run it streams.

### Leadership

One member holds the control-plane lease (the one `cloop hub lease status`
shows) and with it the work that must happen exactly once:

| Duty | Elsewhere |
| --- | --- |
| Retention and the audit-log prune | The control-plane VACUUM is skipped while another member is alive. |
| Scheduled backups | |
| Auto-resume of paused projects | The dispatch goes to the member that can reach the project's executor. |
| The OIDC session janitor | |
| The periodic sweep for orphaned containers and Pods | The startup sweep — sessions, worktrees, workloads — runs only on a member that starts alone. |
| Pruning the bus and the rows of long-gone members | |

A leader that stops gracefully releases the lease and another member takes it
within seconds. One that crashes is replaced as quickly on the same machine,
where its pid is probed, and once its lease lapses — within a minute —
elsewhere. A member that loses the lease is demoted and keeps serving; it is
not shut down, as a pre-cluster hub was.

### Events

What one member produces and every member's dashboards must see travels on a
bus (`hub_bus`): harness output, a run starting or ending, presence (who is
viewing which project), edit-conflict markers, task changes, executor and audit
events, and invalidations — a quota override changed, a session revoked, an
agent deleted, a project registered. Writes are batched every 50ms; every
member polls every 250ms, which is the latency a dashboard sees for an event
produced elsewhere. Events are kept for two minutes. A member that fell further
behind than that — a long pause — learns it missed events and tells its
clients to reload rather than showing them a partial history.

Harness output is also appended to each member's replay buffer, so a dashboard
that connects mid-run to any member gets the backlog.

### Ownership

Some things can be held by only one process: an edge agent's WebSocket, the
stream of a run in progress, a login that is halfway through a redirect, a
chat's history. The member holding one records it in `hub_owners`, and a
request about it that reaches another member is forwarded there:

| Held by one member | Forwarded to it |
| --- | --- |
| A run in progress | Stop, attach, reset, voice; a second Start is refused with `409` and the owner's id |
| An edge agent's connection | Dispatch to the agent, upgrades, virtual executors, lease revocation on cordon, failover redispatch |
| An OIDC login | The callback — the `state` the IdP echoes names the member that began it |
| A Claude Code login | Its code submission and cancel |
| A chat, a suggestion run, an auto-PR | Their follow-up requests |
| A git proxy, Kubernetes monitor or CI relay session | Requests from the sandbox or runner using it |

Anything else — reading state, editing tasks, managing users, grants, quotas
and tokens — is served by whichever member receives it, from the shared
database.

### Also shared

- **Quota counters** are checked and incremented in one database transaction,
  so two members admitting the same tenant at once cannot both slip under a
  limit. Overrides changed on one member are reloaded by all.
- **CI token replay protection**: a token's `jti` presented to one member is
  spent on all of them.
- **Session revocation** evicts the session from every member's cache, not
  only the one that revoked it, and every member closes the dashboard streams
  and sandbox terminals the session opened there (Task 20398). A revoked API
  token is announced the same way; so is what `cloop hub session revoke`,
  `cloop hub token revoke` and `cloop hub user offboard` end, from outside the
  cluster.
- **Refreshing an OIDC session** takes a cluster-wide lock, so a refresh token
  that the provider rotates is redeemed once.
- **`config.yaml` and `projects.json`** are written under a file lock.
- **Project → executor bindings** live in the database every member reads; a
  member also mirrors the bindings it makes in memory, and since Task 20396 a
  bind or unbind on one member — or a deleted virtual executor's — tells the
  others to drop their mirror, so a project rebound through one member (say,
  away from a device that was lost) is not dispatched to the old executor by
  another. The others hear of it within a bus poll (a quarter of a second); a
  Run that reaches one of them sooner still sees the old binding.

---

## Runs, agents and failover

A run is owned by the member that dispatched it, which streams its output,
relays it to the others, and settles it — records the result, merges a
sandbox's result back into the project, releases its leases. When the project's
executor is an edge agent, the dispatching member is always the one holding
that agent's connection: a Start that reaches another member is forwarded
there.

When the owner stops, what happens next depends on where the run's workload is:

| The workload runs on | When its member stops |
| --- | --- |
| An edge agent | The agent reconnects through the load balancer to another member, which **adopts** the run: it keeps streaming and settles it. The harness is not restarted. |
| A container or a Pod | The leader adopts it: the container or Pod is still running, and the leader reattaches to it. |
| The hub host (`localprocess`) | The run was the member's child process and ends with it. The leader settles it as interrupted; auto-resume, if enabled, starts it again. |

On a graceful stop (SIGTERM, a rolling update) a member releases what it holds
on the way out, so adoption starts at once. After a crash it starts when the
member is judged dead — within a heartbeat on the same machine, after 20
seconds elsewhere — except that a run only the leader can adopt waits for a new
leader when the member that died was leading. A run whose owner is gone and
that no member can adopt yet (its agent has not reconnected) keeps its project
busy for two minutes, then is recovered like any run whose process is gone.

A member that finds a run's workload gone or finished when it adopts it settles
the run exactly as the owner would have. A run that was claimed but never
dispatched — the member died between the two — is cleared by the leader so the
project can start again.

An adopting member takes over what the owner held for the run besides its
output (Task 20382): its secret lease — recorded in `secret_leases` under the
member holding it, and named in the run's owner row — which the adopter keeps
alive and releases, and its executor session, which it watches to the run's
end. And what that lease feeds (Task 20383): the run's git proxy and Kubernetes
monitor sessions, recorded in `proxy_sessions` and restored in the adopter's
registries under the ids and tokens the workload holds, with their upstream
credentials re-derived from the lease; the GitHub App token slots recorded in
`app_token_slots`, so the adopter renews the run's App tokens at the recorded
scope; and the run's egress session, named in the owner row and restored with
its byte counters from a member that is gone. An owner that is still alive when
its run moves — its agent reconnected elsewhere — stops serving the lease's
sessions once the adopter has taken the lease, and gives up its claim on them so
requests are forwarded to the adopter; it keeps the run's egress session, which
no member forwards.
A cluster of one is the same: a hub restarted in its own directory adopts the
runs its previous process left, by the same rows. See [a hub restarted
mid-run](executors.md#the-project-comes-back-task-20339) and
[the git proxy's account](git-proxy.md#a-hub-restarted-mid-run).

Executor health probes are divided the same way: an agent is probed by the
member holding its connection, every other executor by the leader, so an
executor is never marked offline by a member that simply cannot see it.

A run whose executor is *lost* — declared unreachable by those probes, rather
than its member stopping — is failed over, and that too happens where it can
(Task 20396). The member probing the executor claims the run's session and
settles its tasks. A replacement on an edge agent is started by the member
holding the agent's connection, which follows it as the project's run and takes
the run's owner row; any other replacement is started and followed by the
member that claimed the session. The member that followed the stranded run
gives it up when it is told so on the bus, or, should that message be lost,
when its own watcher finds the claim in the session store, within ten seconds.
A run whose session a failover claimed is never adopted. When nothing replaces
the run, the project is paused with an `executor_lost` reason by the member
that followed it. See [the replacement is the project's
run](executors.md#the-replacement-is-the-projects-run-task-20396).

---

## The peer channel

A forwarded request travels to the owner's advertised URL whole — WebSocket
upgrades and event streams included — carrying an HMAC over the forwarding
member's id, the receiving member's id, a timestamp, a nonce, the method, the
URI and the original client's address, keyed by a secret the members keep in
the control-plane database (`metadata` key `cluster.peer_key`, created by the
first member).

- **The owner re-authenticates the caller.** Forwarding moves a request; it
  does not vouch for it. The session cookie or token travels with the request
  and is checked again, with the same permissions, as if the owner had been
  reached directly.
- **What the signature proves is that the forwarder is a member.** A client
  cannot present peer headers of its own to skip the per-address rate limit,
  claim another address in the audit trail, or reach the internal endpoints
  under `/api/internal/cluster/` — any of those is refused with `403`. The
  nonce makes a captured request single-use at its recipient within the
  two-minute clock-skew window, and because the signature names the recipient,
  no other member accepts it at all.
- **Anyone who can read the secret can already rewrite every table the hub
  trusts.** It adds no new place to steal from.
- **The channel does not encrypt.** Forwarded requests carry the caller's
  credentials, so members that talk over a network others can observe must
  advertise `https://` URLs. Loopback, and Pod-to-Pod traffic that never leaves
  one node, is what plain HTTP is for — and one node is all a cluster can span.

With `https://` advertise URLs, a member verifies its peers' certificates
against the system roots, its own `ui.tls` certificate (members of one
deployment usually share it, which is what makes a self-signed one work) and
`ui.cluster.peer_ca_file`, under the name `ui.cluster.peer_server_name` — or
the host of `ui.external_url` when that is unset.

---

## Configuration

| Setting | Purpose |
| --- | --- |
| `cloop ui --advertise-url URL` | Where the other members reach this one. |
| `CLOOP_CLUSTER_ADVERTISE_URL` | The same, per process, for supervisors and containers. |
| `CLOOP_CLUSTER_ADVERTISE_HOST` | Just the host, e.g. a Pod IP from the downward API; cloop adds the scheme, brackets an IPv6 address and appends its own port. |
| `ui.cluster.advertise_url` | The same again, from configuration. Per process, so in the instance overlay (`config.ui-<port>.yaml`), never the shared `config.yaml`. |
| `ui.cluster.peer_server_name` | The name peers' certificates are verified against when advertised by IP. |
| `ui.cluster.peer_ca_file` | A PEM bundle trusted for peers' certificates. |
| `ui.cluster.exclusive` | Refuse to start beside any other member, and make any other refuse beside this one: one process, guaranteed. |

The advertise URL is resolved in the order above — flag, URL variable, host
variable, configuration — and defaults to `http://127.0.0.1:<port>`
(`https://` when the member serves TLS), or to the bound address for a member
that listens on one interface rather than loopback or all of them. A member that finds another live
member advertising the same address warns at startup: requests forwarded to
either would reach whichever process answers there.

---

## Operating it

**Upgrades.** Replace members one at a time: start the new one, then stop an
old one. The stopping member hands over its runs and agents before it exits.
Run one build across the cluster otherwise; mixed versions are meant for the
length of a rolling update.

**Schema during an upgrade.** The first member of the new build applies its
migrations, and the old members go on serving the migrated database only as
long as they tolerate every migration they lack: each checks, every time it
opens a database, the verdict the applying build recorded (see
[Rollback](../operations/runbook.md#rollback)). A project's database is opened
for every save of its plan, and the control plane for every CI exchange
recorded and at startup for the quota gauges — so an old member is refused at
its next such write, not later. Tolerating a migration means more than reading
around it: the old member must also leave the new columns alone when it
writes. Every writer since Task 20388 does — it updates the columns it knows
and deletes only the rows that go, and `tests/arch` rejects one that replaces
rows — but builds before Task 20388 replace the rows of `plan_tasks`,
`ci_exchanges` and `quota_counters`, erasing any column they do not know. A
migration appending to one of those tables is therefore recorded
`additive-columns`, which those builds refuse: for the rest of the rollout
their members fail requests that touch the migrated database instead of
erasing the column. To avoid that window, roll the cluster to a build from
Task 20388 on before rolling it to one that carries such a migration. Never mix
in a build from before Task 20226: it has no guard, opens any database and
replaces rows on every save.

**Upgrading from a build before the cluster.** An older hub holds the
control-plane lease without being a member. A current build refuses to start
beside a live one — it would neither forward to it nor see its events — with an
error naming it. Stop the old hub and start the new one; a restart does exactly
that. An old hub that was killed rather than stopped does not block the new one
when both ran on the same machine: its pid is probed. Elsewhere its lease has to
lapse first, within a minute — the new build refuses while the old heartbeat is
recent and waits once a renewal has been missed.

**Maintenance commands** that write state the members hold in memory
(`cloop hub quota set`, `cloop db maintain`) refuse while any member is
serving, not only while one holds the lease. Stop the members, or use the REST
API or dashboard, which every member serves.

**Metrics and logs are per member.** Scrape every member: counters are each
member's own and sum to the cluster's, and the gauges read from the shared
database are exported by the leader alone, so neither is multiplied by the
number of members — see
[which member exports what](../operations/metrics.md#hub-clusters-which-member-exports-what).
What concerns the cluster is logged with `event=cluster` (adopting a run, a forward that failed)
or prefixed `cluster:` on stderr (joining, leading, stepping down).

**Probes.** `/healthz` and `/readyz` describe the member that answers, and
readiness does not depend on leadership: every member serves.

---

## Limits

- **One kernel.** Members must share the database file through one kernel — one
  machine, or one node. There is no multi-node mode.
- **Host-executor runs end with their member**, as described
  [above](#runs-agents-and-failover). Use an isolating executor for runs that
  must survive a member.
- **Credentials minted by a member that dies** are restored by the member that
  adopts their run when they stand on the run's lease or belong to the run — its
  git proxy, Kubernetes monitor and egress sessions (Task 20383), and since Task
  20390 a device workspace's pinned session, whose workspace lease the run's
  owner row names. A request made before the adoption waits up to 60 seconds
  for it. A restored git or Kubernetes session is served by its adopter and a
  request reaching another member is forwarded there, so the proxies'
  `advertise_url` has to reach some live member — a load balancer, or one
  address a restarted process binds again. Egress is not forwarded: a restored
  egress session is served by the adopter's own listener, so the egress
  `advertise_addr` has to reach the adopter, which on a single hub is the
  address the restarted process binds again.
- **A CI relay session** stands on no lease and belongs to no run, so it is
  restored by whichever member receives the job's next call once its holder is
  gone (Task 20390): the record taken over by a conditional write, the session
  held to its rule as the rule stands now, its request budget the one it had
  left. A member that loses the race forwards the call to the winner. Counters
  are flushed every 15 seconds and when a member stops gracefully, so a member
  killed outright can lose at most that much of a session's count. Federation
  is switched per instance — the `cloop ui` port, whose overlay may set
  `ui.ci.enabled` — and each record names the instance whose configuration
  governs it:
  - Switching federation off ends that member's sessions, and a member
    reading the same configuration ends its own when the bus tells it or at
    its next checkpoint.
  - The leader ends the suspended records of every instance whose
    configuration has federation off, running or not.
  - A restore refuses a record whose instance has federation off.
  - An instance that keeps federation on keeps its own.

  What is still forgotten: a Kubernetes Pod's workspace session, minted over a broker
  that keeps no lease records — an init container that fetches after its member
  died gets a 401.
- **Rate limits and connection caps are per member.** Five members admit five
  times the per-address request rate one would.
- **`cloop serve`**, the standalone REST server, is not a member. It sweeps
  orphaned workloads only while no member is serving.

---

## How it is tested

- [`pkg/hubcluster`](../../pkg/hubcluster/) — membership, leadership, the bus
  and ownership against a real database, several nodes in one process.
- [`pkg/ui/cluster_test.go`](../../pkg/ui/cluster_test.go) — two or three
  dashboards on one database: relayed output and presence, forwarded Stops and
  callbacks, refused forgeries, shared quota counters.
- [`tests/cluster`](../../tests/cluster/cluster_test.go) — three real `cloop ui`
  processes behind a load balancer with an enrolled edge agent: a run started on
  one member is dispatched by the agent's member and watched from the third; its
  member is SIGKILLed and a survivor adopts the run without restarting it; Stop
  pressed on a member not streaming a run reaches the one that is; a SIGTERM
  hands a run over. Along the way it scrapes every member's `/metrics`: the
  gauges read from the shared database come from the leader alone, before and
  after a member dies, and the run's start, completion and cancellation are each
  counted once across the cluster. It runs in CI as the `hub-cluster` job,
  against a binary built with the race detector.
- The chart job in CI installs the Helm chart into a kind cluster, scales it to
  three replicas, and asserts one cluster with one leader on one node — before
  and after a rolling restart that replaces every member.
