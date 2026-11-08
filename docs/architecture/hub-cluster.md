# Hub cluster

This page explains how several `cloop ui` processes serve one control plane,
what they share, what each keeps to itself, and what happens when one stops.

Every `cloop ui` process joins the control plane in its working directory as a
**member**. A default install runs one. Start more in the same directory, or
raise `replicaCount` in the Helm chart, and they serve the same projects, runs,
executors, users and secrets behind one load balancer, without session
stickiness:

- A request can land on any member. The few that only one member can answer
  are forwarded to it.
- A dashboard connected to any member sees live output, run state and presence
  from all of them.
- When a member stops (it crashed, was killed, or was replaced by an upgrade),
  the others take over its runs, edge agents and duties.

More members give you availability, upgrades without downtime, and request,
WebSocket and agent connections spread over several processes. They don't give
you a second machine: the control plane is one SQLite database, and every
member reaches it through [one kernel](#what-a-cluster-requires). To *run* more
work, add [executors](executors.md), which is where tasks run anyway.

- [What a cluster requires](#what-a-cluster-requires)
- [Running one](#running-one)
- [What the members share](#what-the-members-share)
- [Runs, agents and failover](#runs-agents-and-failover)
- [A member that stops answering](#a-member-that-stops-answering)
- [Revoking what a dead member held](#revoking-what-a-dead-member-held)
- [No run goes unsupervised](#no-run-goes-unsupervised)
- [The peer channel](#the-peer-channel)
- [Configuration](#configuration)
- [Operating it](#operating-it)
- [Limits](#limits)
- [How it is tested](#how-it-is-tested)

---

## What a cluster requires

**One database file, opened by every member through the same kernel.** That
means members on one machine, or containers and Pods sharing a volume on one
node. SQLite's write-ahead log keeps its index in shared memory, which doesn't
work over a network filesystem, and the event bus's sequence-number cursor
relies on SQLite allowing one writer at a time. A control plane spread over
several machines would need a network database, which cloop doesn't use.

Nothing else is required. Members don't need to share a pid namespace, a process
table or a loopback interface (containers on one node share none of these):
whatever one member needs to know about another, it learns from the database or
over the [peer channel](#the-peer-channel).

**Every member must be able to reach every other member** at the address it
advertises. On one machine that is the default: loopback and the member's own
port. Otherwise, see [configuration](#configuration).

**Every member must see the same project registry.** Registered projects are
listed in `$HOME/.cloop/projects.json` (or under `CLOOP_HOME`), not in the
database, so members with different home directories would each see different
projects. The Helm chart puts `HOME` on the shared volume for this reason.

---

## Running one

### On one machine

```bash
cd /srv/cloop
cloop ui --port 8080 &
cloop ui --port 8081 &
```

Put any load balancer in front of the two. It needs no stickiness or WebSocket
affinity, only a health check (`/healthz` for liveness, `/readyz` to take a
member out of rotation). Unless configured otherwise, each member advertises
`http://127.0.0.1:<port>` to the others, or its address if it listens on one
interface (`--listen`, `ui.listen`). Members without sign-in listen on
`127.0.0.1` only. That is enough on one machine; anywhere else they need
sign-in to listen on the network at all
([Web UI](../reference/configuration.md#web-ui-cloop-ui)).

Settings for one member go in its instance overlay
(`.cloop/config.ui-<port>.yaml`); all members share `.cloop/config.yaml`. Each
member enforces its own merged view of the
[hub-scope keys](../reference/configuration.md#two-dashboards-in-one-directory),
so a policy in one member's overlay (`executors.allow_host_process`,
`sandbox.image_policy`, `executors.git_proxy`) binds that member only, and the
load balancer would decide per request which policy applies. Put policy that
every member must enforce in `config.yaml`.

### In containers on one host

Mount one volume into every container as the state directory, and tell each
container how the others reach it: set `CLOOP_CLUSTER_ADVERTISE_HOST` to the
container's address (cloop adds the scheme and port), or put the whole URL in
`CLOOP_CLUSTER_ADVERTISE_URL`. Containers may share a `hostname:`, because
liveness is keyed to the pid namespace as well as the host.

### On Kubernetes

Raise `replicaCount` in the [Helm chart](../../deploy/README.md#replicas). The
chart pins every replica to the node the ReadWriteOnce volume is attached to,
sets `CLOOP_CLUSTER_ADVERTISE_HOST` to each Pod's IP, switches the Deployment
to a rolling update that starts a replacement before a member leaves, and
refuses to render more than one replica without persistence.

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

The command reads the database directly, so it works even with every member
down, which is when you most need to know who was serving and who led. It also
lists what each member holds that the others forward to it. Use `--json` for
scripts. `GET /api/cluster` (permission `executor.manage`) is the same view from
a running member, plus its bus counters. Every response carries
`X-Cloop-Served-By: <member>`, naming the member that answered.

---

## What the members share

Members share four things, all through the database
([`pkg/hubcluster`](../../pkg/hubcluster/hubcluster.go), tables from
`migrations/0052_hub_cluster.sql`).

### Membership

Each member keeps a row in `hub_members` and renews it every 5 seconds. A
member that hasn't renewed it for 20 seconds is dead, and one that shuts down
gracefully says so and is dead at once. Members on the same machine and in the
same pid namespace also check each other's pid, so the most common crash (a
supervisor restarting a killed process within seconds) is noticed within a
heartbeat instead of after the TTL. A pid from another namespace is never
checked, since it would name no process or the wrong one.

A member also announces on the [bus](#events) when it joins or leaves, so the
others learn of it within a poll instead of at their next heartbeat. This
matters most for joining: a member that thinks it is alone publishes nothing,
so a newcomer it hasn't noticed would miss the start of every run it streams.

### Leadership

One member holds the control-plane lease (the one `cloop hub lease status`
shows), and with it the duties that must run on one member only:

| Duty | Elsewhere |
| --- | --- |
| Retention and the audit-log prune | The control-plane VACUUM is skipped while another member is alive. |
| Scheduled backups | |
| Auto-resume of paused projects | The dispatch goes to the member that can reach the project's executor. |
| The OIDC session janitor | |
| The periodic sweep for orphaned containers and Pods | The startup sweep (sessions, worktrees, workloads) runs only on a member that starts alone. |
| Pruning the bus and the rows of long-gone members | |

A leader that stops gracefully releases the lease, and another member takes it
within seconds. One that crashes is replaced as quickly on the same machine,
where its pid is checked, and elsewhere once its lease lapses, within a minute.
A member that loses the lease is demoted and keeps serving.

### Events

Anything one member produces that every member's dashboards need travels on a
bus (`hub_bus`): harness output, runs starting and ending, presence (who is
viewing which project), edit-conflict markers, task changes, executor and audit
events, and invalidations (a quota override changed, a session revoked, a
static token retired, an agent deleted, a project registered). Writes are
batched every 50ms and every member polls every 250ms, which is the delay a
dashboard sees for an event from another member. Events are kept for two
minutes. A member that falls further behind (after a long pause, say) learns
that it missed events and tells its clients to reload instead of showing a
partial history.

Harness output also goes into each member's replay buffer, so a dashboard that
connects to any member mid-run gets the backlog.

### Ownership

Some things only one process can hold: an edge agent's WebSocket, the stream of
a run in progress, a login halfway through a redirect, a chat's history. The
member holding one records it in `hub_owners`, and a request about it that
reaches another member is forwarded to the holder:

| Held by one member | Forwarded to it |
| --- | --- |
| A run in progress | Stop, attach, reset, voice. A second Start is refused with `409` and the owner's id. |
| An edge agent's connection | Dispatch to the agent, upgrades, virtual executors, lease revocation on cordon, failover redispatch |
| A device forwarder's connection | The dashboard's probe of its device, and a run's device stream, which the member dispatching the run opens over the peer channel |
| An OIDC login | The callback (the `state` the IdP echoes back names the member that started the login) |
| A Claude Code login | Its code submission and cancel |
| A chat, a suggestion run, an auto-PR | Their follow-up requests |
| A git proxy, Kubernetes monitor or CI relay session | Requests from the sandbox or runner using it |

Everything else (reading state, editing tasks, managing users, grants, quotas
and tokens) is served from the shared database by whichever member receives it.

### Also shared

- **Quota counters** are checked and incremented in one database transaction,
  so two members admitting the same tenant at once can't both slip under a
  limit. An override changed on one member is reloaded by all. A run's
  concurrency slot is recorded on its owner row and moves with the run: the
  member that settles the run gives it back, and a member that hands the run
  over gives nothing back. Runs dispatched by an older build (v0.0.7 or
  earlier) still keep their slot permanently when they move, so each rolling
  update leaves every tenant with such a run in flight one slot short.
- **CI token replay protection**: a token's `jti` presented to one member is
  spent on all of them.
- **Session revocation** evicts the session from every member's cache, and
  every member closes the dashboard streams and sandbox terminals the session
  opened on it. Revoked API tokens are announced the same way, as is anything
  `cloop hub session revoke`, `cloop hub token revoke` and
  `cloop hub user offboard` end from outside the cluster.
- **Offboarding reaches every member's Claude Code homes.** A per-user login
  lives under the config directory of the process that created it, not in the
  database, so members running as different users or in separate container
  filesystems each keep a copy. When you offboard someone from the dashboard,
  the member serving the request removes its copy and calls
  `/api/internal/cluster/offboard/claude` on every live peer.
  `cloop hub user offboard` isn't a member, so it puts the request on the bus
  (topic `offboard`) and reads back each member's answer, addressed to it.
  Members advertise their root directory in their member row (`claude_homes`),
  so the report names any tree a stopped member left on a host that is still
  up. A member acts on another process's request only for an identity the
  control plane denies, and a member that doesn't answer is reported (see
  [offboarding](../security/model.md#offboarding-what-a-departed-identity-keeps)).
- **Device forwarders.** Every member lists forwarders from the shared records,
  not only its own sessions, and reads from a forwarder's owner row whether it
  is connected and through which member. A forwarder or binding revoked on any
  member, or with `cloop forward revoke|unbind`, is announced on the bus (topic
  `invalidate`, key `forwarder`): the member holding the forwarder's tunnel
  drops it at once, and every member detaches the device from the runs it
  relays it to. Each member acts only on what the database confirms and
  re-checks what it holds every few seconds, so a member that missed the
  announcement still detaches within seconds. The holder's session also
  re-reads its forwarder's record every five seconds.
- **Refreshing an OIDC session** takes a cluster-wide lock, so a refresh token
  the provider rotates is redeemed only once.
- **`config.yaml` and `projects.json`** are written under a file lock.
- **Project → executor bindings** are stored in the database every member
  reads, and each member also keeps an in-memory copy of the bindings it makes.
  A bind or unbind on one member, or deleting a virtual executor, tells the
  others to drop their copies, so a project you rebind through one member (away
  from a lost device, say) isn't dispatched to the old executor by another. The
  others hear of it within one bus poll (a quarter of a second); a Run that
  reaches one of them sooner still sees the old binding.

---

## Runs, agents and failover

The member that dispatched a run owns it: it streams the run's output, relays
it to the other members, and settles the run (records the result, merges a
sandbox's result back into the project, releases the run's leases). For an edge
agent, the dispatching member is always the one holding the agent's connection,
and a Start that reaches another member is forwarded there.

When the owner stops, what happens next depends on where the run's workload
runs:

| The workload runs on | When its member stops |
| --- | --- |
| An edge agent | The agent reconnects through the load balancer to another member, which **adopts** the run: it keeps streaming and settles it. The harness is not restarted. |
| A container or a Pod | The leader adopts the run and reattaches to the container or Pod, which is still running. |
| The hub host (`localprocess`) | A killed member's child process is reparented and carries on. A leader on the same machine and in the same pid namespace adopts the run: it can't stream the output, which went to a pipe the dead member held, but it watches the process to its end and settles the run. The run's credentials don't survive. As soon as a member sees the owner die, it wipes the lease directories the dead member materialised in `/dev/shm`, and the run carries on without them. A leader in another pid namespace can't see the process, so it settles the run as interrupted, and auto-resume, if enabled, starts it again. A member stopped gracefully ends its runs first. |

On a graceful stop (SIGTERM, a rolling update), a member releases what it holds
on the way out, so adoption starts at once. After a crash it starts when the
member is judged dead: within a heartbeat on the same machine, after 20 seconds
elsewhere. If the dead member was the leader, a run only the leader can adopt
waits for a new leader. A run whose owner is gone and that no member can adopt
yet (its agent hasn't reconnected) keeps its project busy for two minutes, then
is recovered like any run whose process is gone.

An adopter that finds the workload gone or finished settles the run as the
owner would have. A run that was claimed but never dispatched (the member died
in between) is cleared by the leader so the project can start again. One whose
dispatch reached its executor is cleared only after any workload it may have
started is stopped ([No run goes unsupervised](#no-run-goes-unsupervised)).

Adopting the workload of a container, Pod or host process claims its row in
`executor_handles` with a compare-and-swap on the member the row named before.
A member's drivers adopt only their own rows, plus a stopped member's when this
member adopts for it (the leader, or a member serving alone), so one workload
never gets two log pumps, two kill timers or, for a Pod, two lease renewers.
Rows also carry what the dispatcher kept in memory and an adopter needs: where
a container's credential files are staged on the host (the directory, its
identity, and each file's lease and grant, never the contents), and which key
of a Pod's lease Secret each file is projected from. So an adopter can wipe a
container's staged files when the run ends, revoke them without removing the
container, and refresh a GitHub App token delivered as a file to a container or
Pod, which would otherwise stop working an hour into the adopted run. It trusts
a staged directory only if it is under a staging base, named the way the driver
names them, and still the same directory (the sandbox user owns it and could
have replaced it). If a stage can't be accounted for, a revocation removes the
container instead.

Besides the output, the adopter takes over what the owner held for the run:

- Its secret lease, recorded in `secret_leases` under the member holding it and
  named in the run's owner row. The adopter keeps it alive and releases it.
- Its executor session, which the adopter watches to the run's end.
- What the lease feeds: the run's git proxy and Kubernetes monitor sessions,
  recorded in `proxy_sessions` and restored in the adopter's registries under
  the ids and tokens the workload holds, with their upstream credentials
  derived again from the lease; the GitHub App token slots in
  `app_token_slots`, so the adopter renews the run's App tokens at the recorded
  scope; and the run's egress session, named in the owner row and restored with
  its byte counters when its member is gone.

An owner still alive when its run moves (its agent reconnected elsewhere) stops
serving the lease's sessions once the adopter has taken the lease, and gives up
its claim on them so requests are forwarded to the adopter. It keeps the run's
egress session, which no member forwards, and ends it when the run ends, which
it learns from the run's owner row. The adopter keeps naming that session in
the owner row as one a live member serves, and takes it over if that member
stops first.

**A takeover the store cannot decide is tried again.** An attempt to take over
a credential is decided once it has a final result: taken over, held by the
member that adopted the run first, released, revoked and taken back, or refused
because it lapsed or its grants no longer allow it. It is undecided when the
secret store couldn't be read for a moment, the database was locked, the disk
was at its floor, or a KMS was down for a member that hadn't opened the store
yet.

The adopter keeps an undecided credential (a lease, the workspace lease or an
egress session) on the run's owner row beside what it holds, marked as
undecided, and retries it: after two seconds, then with the wait doubling up to
a minute, until an attempt decides it or the credential's recorded expiry
passes. A request presenting a session the credential feeds brings the next
attempt forward, and a member that adopts the run later finds the id on the row
and tries too. An attempt takes the credential only while its member still owns
the run (the broker checks immediately before its conditional write), so a retry after
the run moved never takes back what the new owner holds, and an attempt that
finds its takeover ended meanwhile lets go of what it took.

While a takeover is undecided, the run's event history has a `lease_takeover`
row saying so, `cloop hub doctor` and **Settings → Hub health** warn
`runs.lease_takeovers`, and `cloop_lease_takeovers_total` counts the attempts.
Once the credential is taken over, a second row says so and what the lease
feeds is restored. A credential still undecided when it lapses or the run ends
is recorded on the run as failed, and the run carries on without it.

The same applies to a cluster of one: a hub restarted in its own directory
adopts the runs its previous process left, from the same rows. See
[a hub restarted mid-run](executors.md#the-project-comes-back-task-20339) and
[the git proxy's account](git-proxy.md#a-hub-restarted-mid-run).

Executor health probes are split the same way: the member holding an agent's
connection probes that agent, and the leader probes every other executor, so a
member that can't see an executor never marks it offline.

---

## A member that stops answering

A heartbeat only shows that one goroutine runs and one database write
succeeds. A member can keep both going while everything that serves requests is
stuck: a deadlocked handler, a listener that stopped accepting, an advertise
address that leads nowhere. Without another check, requests forwarded to such a
member would wait without limit, and its runs would never be adopted.

So every 5 seconds each member sends every live peer a signed
`GET /api/internal/cluster/ping` over the [peer channel](#the-peer-channel),
with a 5-second timeout. A peer that has failed every probe for the member TTL
(20 seconds), and at least twice, is **unresponsive** to that member, which then
treats it as down for everything that hands work over:

- What it owns (runs, agent sockets, logins and conversations in progress) is
  adopted by whichever member would adopt it from a member that died.
- Nothing more is forwarded to it, and requests already waiting on it fail at
  once with a `502` saying it is not answering.
- Its handle rows and host-process lease directories are treated as a stopped
  member's.

An unresponsive leader keeps its lease, which is renewed in the database, so
the member serving longest adopts in its place. Each member reaches its own
verdict, and the peer's first answer clears it. Adoption is a compare-and-swap
on the owner row, so members that judge differently still produce one adopter,
and a member judged wrongly (slow, not stuck) finds its run adopted at its next
ownership check and lets it go, as a member paused past its heartbeat TTL does.
`GET /api/cluster` lists an unresponsive member as `alive` with `unresponsive`
set.

A forwarded request also has its own limit: it waits at most 6 minutes for the
owner's response headers, then fails with a `502`. That is longer than the
slowest requests a member answers only once the work is done (a voice
transcription or an agent's `cloop init`, each limited to 5 minutes). Once the
headers arrive, the response streams for as long as it lasts.

---

## Revoking what a dead member held

A run's secret lease is held by one member, the one that dispatched or adopted
the run, which keeps it alive and releases it. When that member dies, nobody
holds the lease until another member adopts the run. Builds before v0.0.5
answered a revocation in that window with `404 no lease with that id is open`,
recorded nothing, and let the adopter take the lease over and restore the git
proxy and Kubernetes monitor sessions it fed, undoing an incident responder's
revocation without a trace. Current builds handle the window like this:

- **A lease revocation is recorded** in `secret_lease_revocations` before any
  holder is asked, and the record outlives the lease's. The broker refuses to
  hand a revoked lease to a new holder, so the member adopting the run takes
  the material back from the workload instead of restoring anything, and
  retires the lease's record. The broker also refuses to extend a revoked
  lease, so a live holder the revocation couldn't reach lets it lapse, and its
  own lease janitor takes it back within one pass.
- **The answer is `202`, not `404`,** when nothing reachable holds the lease
  because its member is gone. The revocation is recorded, and each holder it
  waits for is listed under `pending` with when it takes effect: when that
  member's run is reached. A member the revocation couldn't ask (in the seconds
  after a death, usually one not yet judged dead) is listed there too, as
  `hub member <id>`, instead of as an `unreachable` holder. The record binds it
  either way: if it is still running, its lease janitor takes the credential
  back, and if it stopped, the member that adopts its run does. `200` still
  means every holder answered.
- **The member that adopts a dead member's runs reaches them at once**, instead
  of at its next sweep. When a revocation (of a lease, a grant or a lapsed
  lease) concerns a lease a dead member held, the member that would adopt that
  member's run adopts it first: the leader for a container, Pod or host
  process, the member holding the agent's socket for an agent. The leader also
  rehydrates the dead member's handle rows into its own drivers, so a container
  or Pod whose run can't be adopted at all (its claim was never recorded) is
  still reached through its executor. What adoption took back is reported as
  part of the revocation.
- **A grant revocation lists such a lease as `pending`** until the leader has
  reached its workload, so it never reports `revoked` while a dead member's
  container still holds the material.
- **Host-process lease directories are wiped when their member dies.** A member
  that sees another die wipes the directories the dead member materialised in
  `/dev/shm` on this machine. One it can't see (on another machine or in
  another mount namespace) stays on record for a process that can.
- **A cordon whose agent's member can't be asked** (dead but not yet judged
  so) records each lease issued to the agent as revoked, and the cordoning
  member revokes it.

A revocation stays pending until a process finds the material gone from every
holder. The lease janitor retries pending ones, backing off to every half hour,
and the leader prunes enforced ones after 30 days.

---

## No run goes unsupervised

Before asking the executor for anything, the member writes a **dispatch
intent** (the run id, the executor, itself and the run's leases) to
`dispatch_intents`, so the dispatch is on record before its workload exists,
and marks the project's run claim with the run id. It adds the workload's
handle to the intent once it has one, and retires the intent once the run is on
record or the workload ends. Every step of becoming supervised must succeed:

- If the intent, the session record (`executor_sessions`, which failover reads)
  or the run's owner row can't be written, the dispatch is refused: the
  workload, if it exists, is stopped, its lease released and its egress session
  closed, and `POST /api/run` answers `503` with the storage error. Otherwise
  the workload would run untracked, never failed over or adopted, with its
  credentials never taken back after its member died.
- An intent whose member died names a workload no member supervises. The member
  that would have adopted its run stops it, through the handle its driver
  recorded (rehydrated from the dead member's row) or by its run id (a
  container's `cloop.spec.run_id` label, a Pod's `cloop.dev/run-id`), and takes
  its leases back and retires their records. Only then does the leader clear
  the dead member's claim. Meanwhile a claim whose dispatch reached its
  executor holds its project for the orphan grace period, so the project can't
  be started again beside the workload.

An intent whose run turns out to be on record after all (the member died
between recording the run and retiring the intent) is retired, and the run is
left to adoption.

A run whose executor is *lost* (declared unreachable by the health probes, as
opposed to its member stopping) is failed over, with each step done by the
member able to do it. The member probing the executor claims the run's session
and settles its tasks. A replacement on an edge agent is started by the member
holding the agent's connection, which follows it as the project's run and
takes the run's owner row; any other replacement is started and followed by
the member that claimed the session. The member that followed the stranded
run gives it up when the bus tells it to or, if that message is lost, when its
own watcher finds the claim in the session store, within ten seconds. A run whose session a
failover claimed is never adopted. If nothing replaces the run, the member that
followed it pauses the project with the reason `executor_lost`. See
[the replacement is the project's run](executors.md#the-replacement-is-the-projects-run-task-20396).

---

## The peer channel

A forwarded request goes whole to the owner's advertised URL, WebSocket
upgrades and event streams included. It carries an HMAC over the forwarding
member's id, the receiving member's id, a timestamp, a nonce, the method, the
URI and the original client's address, keyed by a secret the members keep in
the control-plane database (`metadata` key `cluster.peer_key`, created by the
first member).

- **The owner re-authenticates the caller.** The session cookie or token
  travels with the request and is checked again, with the same permissions, as
  if the caller had reached the owner directly.
- **The signature proves that the forwarder is a member.** A client can't send
  its own peer headers to skip the per-address rate limit, claim another
  address in the audit trail, or reach the internal endpoints under
  `/api/internal/cluster/`; each is refused with `403`. The nonce makes a
  captured request single-use at its recipient within the two-minute clock-skew
  window, and since the signature names the recipient, no other member accepts
  it at all.
- **Anyone who can read the secret can already rewrite every table the hub
  trusts**, so keeping it in the database gives an attacker nothing new.
- **The channel does not encrypt.** Forwarded requests carry the caller's
  credentials, so members that talk over a network others can observe must
  advertise `https://` URLs. Plain HTTP is for loopback and for Pod-to-Pod
  traffic that never leaves one node, and a cluster can't span more than one
  node.

With `https://` advertise URLs, a member verifies its peers' certificates
against the system roots, its own `ui.tls` certificate (members of one
deployment usually share it, which is what makes a self-signed one work) and
`ui.cluster.peer_ca_file`, for the name in `ui.cluster.peer_server_name`, or the
host of `ui.external_url` when that is unset.

---

## Configuration

| Setting | Purpose |
| --- | --- |
| `cloop ui --advertise-url URL` | Where the other members reach this one. |
| `CLOOP_CLUSTER_ADVERTISE_URL` | The same, per process, for supervisors and containers. |
| `CLOOP_CLUSTER_ADVERTISE_HOST` | Only the host, such as a Pod IP from the downward API. cloop adds the scheme, brackets an IPv6 address and appends its own port. |
| `ui.cluster.advertise_url` | The same, from configuration. It is per process, so it belongs in the instance overlay (`config.ui-<port>.yaml`), never the shared `config.yaml`. |
| `ui.cluster.peer_server_name` | The name peers' certificates are verified against when they advertise an IP address. |
| `ui.cluster.peer_ca_file` | A PEM bundle trusted for peers' certificates. |
| `ui.cluster.exclusive` | Refuse to start beside any other member, and make any other member refuse to start beside this one. |

The advertise URL is resolved in the order above (flag, URL variable, host
variable, configuration) and defaults to `http://127.0.0.1:<port>` (`https://`
when the member serves TLS), or to the bound address for a member that listens
on one interface rather than on loopback or all interfaces. A member that finds
another live member advertising the same address warns at startup, because
requests forwarded to either would reach whichever process answers there.

---

## Operating it

**Upgrades.** Replace members one at a time: start a new one, then stop an old
one, which hands over its runs and agents before it exits. Mixed versions are
meant only for the length of a rolling update; otherwise run one build on every
member. CI rehearses this on every push to main, from the latest published
release with the real release binary beside the new build. See
[Rehearsing a rolling upgrade](../operations/runbook.md#rehearsing-a-rolling-upgrade)
for what it checks and its last result.

**Schema during an upgrade.** The first member on the new build applies its
migrations. The old members keep serving the migrated database only while they
tolerate every migration they lack: each time an old member opens a database,
it checks the verdict the applying build recorded (see
[Rollback](../operations/runbook.md#rollback)). A project's database is opened
for every save of its plan, and the control plane's for every recorded CI
exchange and at startup for the quota gauges, so an old member is refused at
its next such write. Tolerating a migration also means leaving the new columns
alone when writing. Every writer from v0.0.5 on does: it updates only the
columns it knows and deletes only the rows that go, and `tests/arch` rejects a
writer that replaces rows. Builds before v0.0.5 replace the rows of
`plan_tasks`, `ci_exchanges` and `quota_counters`, erasing any column they
don't know. So a migration that adds columns to one of those tables is recorded
as `additive-columns`, which those builds refuse: for the rest of the rollout
their members fail requests that touch the migrated database instead of erasing
the column. To avoid that window, roll the cluster to v0.0.5 or later before
rolling it to a build that carries such a migration. Never mix in a build older
than v0.0.1: it has no guard, opens any database and replaces rows on every
save.

**Upgrading from a build before the cluster.** A hub from before clustering
holds the control-plane lease without being a member. A current build refuses
to start beside a live one, with an error naming it, because it could neither
forward to it nor see its events. Stop the old hub and start the new one (a
restart does this). An old hub that was killed instead of stopped doesn't block
the new one if both ran on the same machine, because its pid is checked.
Elsewhere its lease has to lapse first, within a minute: the new build refuses
while the old heartbeat is recent and waits once a renewal has been missed.

**Maintenance commands** that write state the members hold in memory
(`cloop hub quota set`, `cloop db maintain`) refuse while any member is
serving, whether or not it holds the lease. Stop the members, or use the REST
API or the dashboard, which every member serves.

**Metrics and logs are per member.** Scrape every member. Counters are each
member's own and add up to the cluster's, and only the leader exports the
gauges read from the shared database, so neither is multiplied by the number of
members (see
[which member exports what](../operations/metrics.md#hub-clusters-which-member-exports-what)).
Cluster events are logged with `event=cluster` (adopting a run, a failed
forward) or prefixed `cluster:` on stderr (joining, leading, stepping down).

**Probes.** `/healthz` and `/readyz` describe the member that answers.
Readiness doesn't depend on leadership, because every member serves.

---

## Limits

- **One kernel.** Members must share the database file through one kernel, on
  one machine or one node. There is no multi-node mode.
- **Host-executor runs outlive a killed member without their credentials**, as
  described [above](#runs-agents-and-failover), and only a member in their pid
  namespace can watch them. Use an isolating executor for runs that must
  survive a member intact.
- **Credentials minted by a member that dies** are restored by the member that
  adopts their run if they depend on the run's lease or belong to the run: its
  git proxy, Kubernetes monitor and egress sessions, and a device workspace's
  pinned session, whose workspace lease the run's owner row names. If the lease
  was revoked meanwhile, nothing is restored and the material is taken back
  ([Revoking what a dead member held](#revoking-what-a-dead-member-held)). A
  request made before the adoption waits up to 60 seconds for it. A restored
  git or Kubernetes session is served by its adopter, and requests reaching
  another member are forwarded there, so the proxies' `advertise_url` has to
  reach some live member: a load balancer, or an address a restarted process
  binds again. Egress is not forwarded: a restored egress session is served by
  the adopter's own listener, so the egress `advertise_addr` has to reach the
  adopter, which on a single hub is the address the restarted process binds
  again. A run that moves between two live members keeps its egress session on
  the member that served it until the run ends, or until that member stops and
  the run's owner takes it over.
- **A takeover the store cannot decide** is retried until the credential's
  recorded expiry ([above](#runs-agents-and-failover)). Meanwhile what the
  credential feeds is not served (a request that needs it waits up to 60
  seconds, as before an adoption), and a fault that outlasts the lease costs the
  run its credentials, recorded on its history as a failed takeover.
- **A CI relay session** depends on no lease and belongs to no run, so once its
  holder is gone, whichever member receives the job's next call restores it: it
  takes the record over with a conditional write, holds the session to its rule
  as the rule stands now, and keeps the request budget it had left. A member
  that loses the race forwards the call to the winner. Counters are flushed
  every 15 seconds and when a member stops gracefully, so a member killed
  outright loses at most 15 seconds of a session's count. Federation is
  switched per instance (the `cloop ui` port, whose overlay may set
  `ui.ci.enabled`), and each record names the instance whose configuration
  governs it:
  - Switching federation off ends that member's sessions. A member reading the
    same configuration ends its own when the bus tells it to, or at its next
    checkpoint.
  - The leader ends the suspended records of every instance whose configuration
    has federation off, running or not.
  - A restore refuses a record whose instance has federation off.
  - An instance that keeps federation on keeps its own.

  A Kubernetes Pod's workspace session is also taken over. Its lease and
  session are recorded when the member that dispatched the Pod mints them, and
  the member that adopts the Pod (the leader, for a dead member's) restores the
  session, so an init container that fetches after its member died is served,
  then closes it once the fetch is confirmed
  (`TestAPodsWorkspaceSessionIsAdoptedByAnotherMember`). A fetch made before the
  adoption waits for it, up to a minute. One that outlasts a slow leader
  election is refused, a residual risk listed in the
  [security model](../security/model.md#what-is-not-mitigated).
- **Rate limits and connection caps are per member.** Five members admit five
  times the per-address request rate one would.
- **`cloop serve`**, the standalone REST server, is not a member. It sweeps
  orphaned workloads only while no member is serving.

---

## How it is tested

- [`pkg/hubcluster`](../../pkg/hubcluster/): membership, leadership, the bus
  and ownership against a real database, with several nodes in one process.
- [`pkg/ui/cluster_test.go`](../../pkg/ui/cluster_test.go): two or three
  dashboards on one database: relayed output and presence, forwarded Stops and
  callbacks, refused forgeries, shared quota counters.
- [`pkg/ui/run_supervision_test.go`](../../pkg/ui/run_supervision_test.go) and
  [`run_supervision_cluster_test.go`](../../pkg/ui/run_supervision_cluster_test.go):
  a dead holder's lease is revoked (`202`, recorded) and taken back on adoption
  instead of taken over. A dispatch whose session record the database refuses
  (`PRAGMA query_only`) is refused and its workload stopped. A dead member's
  unrecorded dispatch is reaped before its claim is cleared. A member that
  heartbeats without answering has its run adopted. A dead member's host lease
  directory is wiped before its record goes. A workload row is adopted by one
  member.
- [`pkg/hubcluster/probe_test.go`](../../pkg/hubcluster/probe_test.go): a
  forward to a member that never answers is bounded by the header timeout. A
  member that heartbeats but doesn't answer is judged unresponsive, its
  requests fail and what it owns is orphaned. An unresponsive leader's adoption
  is done in its place.
- [`tests/cluster`](../../tests/cluster/cluster_test.go): three real `cloop ui`
  processes behind a load balancer, with an enrolled edge agent. A run started
  on one member is dispatched by the agent's member and watched from the third.
  That member is killed with SIGKILL and a survivor adopts the run without
  restarting it. Stop pressed on a member not streaming a run reaches the one
  that is. A SIGTERM hands a run over, and each run gives its tenant's
  concurrency slot back on the member that settles it. Along the way the test
  scrapes every member's `/metrics`: the gauges read from the shared database
  come from the leader alone, before and after a member dies, and the run's
  start, completion and cancellation are each counted once across the cluster.
  It runs in CI as the `hub-cluster` job, against a binary built with the race
  detector.
- [`pkg/ui/takeover_retry_test.go`](../../pkg/ui/takeover_retry_test.go): a
  lease whose takeover a locked store refuses a few times is kept on the owner
  row as undecided and taken over once the store answers; its git and
  Kubernetes sessions are served again and a push lands. The same for a
  workspace lease. One the store refuses past the lease's expiry, or past its
  run, is recorded on the run as failed. And both halves of a run moving
  between two live members: the adopter keeps the egress session named and
  takes it over when its holder stops, and the holder ends it when the run
  ends.
- [`tests/e2e/hubrestart_takeover_test.go`](../../tests/e2e/hubrestart_takeover_test.go):
  a real hub is killed with SIGKILL mid-run, with its lease's record made
  unreadable. The restarted process warns `runs.lease_takeovers`, counts
  retries and takes the lease over once the record is repaired, and the run
  settles as in the other restart scenarios.
- [`tests/cluster/revocation_test.go`](../../tests/cluster/revocation_test.go):
  two real members. The one holding a run's lease is killed with SIGKILL, and
  the lease, then its grant, are revoked through the survivor. For a container
  run the credential is gone from the sandbox and its staged copy from the
  host, and the lease is never restored on adoption. For a host-process run the
  dead member's `/dev/shm` directory is wiped while the reparented process runs
  on. Part of the `hub-cluster` job.
- The chart job in CI installs the Helm chart into a kind cluster, scales it to
  three replicas, and checks for one cluster with one leader on one node,
  before and after a rolling restart that replaces every member.
- [`tests/upgrade`](../../tests/upgrade/main_test.go): a rolling upgrade from
  the latest published release, verified against the release identity before
  it runs. Two release members and a release agent's device run with its lease
  and proxy sessions, then a member of the build under test that migrates while
  the release members keep serving, then the release members stopped one at a
  time. Every column the new build added must survive the release's writes, the
  run must settle on the new build with its credentials, and the release must
  refuse or tolerate the migrated database as the runbook's Rollback section
  says. CI's *Upgrade rehearsal* job runs it on every push, and the release
  workflow runs it from the previous release. See
  [Rehearsing a rolling upgrade](../operations/runbook.md#rehearsing-a-rolling-upgrade).
