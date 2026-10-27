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
events, and invalidations — a quota override changed, a session revoked, a
static token retired, an agent deleted, a project registered. Writes are batched every 50ms; every
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
| A device forwarder's connection | The dashboard's probe of its device; a run's device stream, which the member dispatching the run opens over the peer channel (Task 20430) |
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
  limit. Overrides changed on one member are reloaded by all. A run's
  concurrency slot is recorded on its owner row and goes where the run goes:
  the member that settles the run gives it back, and a member that lets go of
  a run gives nothing back (Task 20452). Before, a run that moved between
  members kept its slot for good — every rolling update narrowed every tenant
  with a run in flight by one. A run a build from before that dispatched still
  does.
- **CI token replay protection**: a token's `jti` presented to one member is
  spent on all of them.
- **Session revocation** evicts the session from every member's cache, not
  only the one that revoked it, and every member closes the dashboard streams
  and sandbox terminals the session opened there (Task 20398). A revoked API
  token is announced the same way; so is what `cloop hub session revoke`,
  `cloop hub token revoke` and `cloop hub user offboard` end, from outside the
  cluster.
- **Offboarding reaches every member's Claude Code homes** (Task 20400). A
  per-user login lives under the config directory of the process that made
  it, not in the database, so members under different users or container
  filesystems keep one copy each. The member serving a dashboard offboarding
  removes its own and calls `/api/internal/cluster/offboard/claude` on every
  live peer; `cloop hub user offboard`, which is no member, puts the request on
  the bus (topic `offboard`) and reads each member's answer back, addressed to
  it. Each member advertises its root in its member row (`claude_homes`), so a
  stopped member's tree on a host that is still up is named rather than
  forgotten. A member acts on another process's word only for an identity the
  control plane denies, and a member that does not answer is reported — see
  [offboarding](../security/model.md#offboarding-what-a-departed-identity-keeps).
- **Device forwarders** (Task 20430). Every member lists a forwarder from the
  shared records — connected, and through which member, from its owner row —
  rather than from its own sessions alone. A revoked forwarder or binding, on
  any member or from `cloop forward revoke|unbind`, is announced on the bus
  (topic `invalidate`, key `forwarder`): the member holding the forwarder's
  tunnel drops it at once, and every member detaches the device from the runs
  it relays it to. Each acts only on what the database confirms, and each
  re-checks what it holds every few seconds, so a member that missed the
  notice still detaches in seconds; the holder's own session also re-reads its
  forwarder's record every five.
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
| The hub host (`localprocess`) | A member that is killed does not take its child with it: the run's process is reparented and carries on. The leader adopts it when it runs on the same machine, in the same pid namespace — it cannot stream the process's output, which went to a pipe the dead member held, but it watches the process to its end and settles the run. Its **credentials do not survive**: the lease directories the dead member materialised in `/dev/shm` are wiped as soon as a member sees it die (Task 20419), so the run carries on without them. A leader in another pid namespace cannot see the process and settles the run as interrupted; auto-resume, if enabled, starts it again. A member stopped gracefully ends its runs first. |

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
project can start again; one whose dispatch got as far as its executor is
cleared only once the workload it may have started is stopped
([No run goes unsupervised](#no-run-goes-unsupervised)).

Adopting a container's, Pod's or host process's workload claims its row in
`executor_handles` (Task 20419): the row names the member that adopted it, by
a compare-and-swap on the member it named before, and a member's drivers adopt
only their own rows and those of a stopped member when that member is the one
adopting for it — the leader, or a member serving alone. A member started later
used to adopt every row a dead member left, alongside the member that had taken
the run over: two log pumps, two kill timers and, for a Pod, two lease renewers
for one workload. Rows also carry what the dispatcher kept in memory and an
adopter needs: where a container's credential files are staged on the host
(the directory, its identity and each file's lease and grant — never the
contents) and which key of a Pod's lease Secret each file is projected from. An
adopter wipes a container's staged files when it ends, revokes them without
removing the container, and refreshes a GitHub App token delivered as a file in
a container or a Pod, as the dispatcher would have; before, GitHub stopped
honouring such a token an hour into an adopted run. A staged directory is
trusted only if it is under a staging base, named as the driver names them and
still the directory it was — the sandbox user owns it and could have replaced
it — and a stage that cannot be accounted for makes a revocation remove the
container instead.

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
requests are forwarded to the adopter. It keeps the run's egress session, which
no member forwards, and since Task 20451 ends it when the run ends, which it
learns from the run's owner row: before, it renewed the session for up to a day
because it could no longer ask the device whether the run was over. The adopter
keeps naming that session in the owner row, as one a live member serves, and
takes it over if that member stops first.

**A takeover the store cannot decide is tried again** (Task 20451). An attempt
to take a credential over is decided when it ends one way or the other for
good: taken over; held by the member that adopted the run first; released;
revoked, and taken back; refused because it lapsed or its grants no longer
allow it. It is undecided when the secret store could not be read for a moment,
the database was locked, the disk was at its floor, or a KMS was down for a
member that had not opened the store yet. The adopter keeps an undecided
credential — a lease, the workspace lease or an egress session — on the run's
owner row beside what it holds, names it there as undecided, and tries again
itself: two seconds later, then with the wait doubling to a minute, until an
attempt decides it or the credential's recorded expiry passes. A request
presenting a session it feeds brings the next attempt forward, and a member
adopting the run after this one finds the id on the row and tries too. An
attempt takes the credential only while its member still owns the run — the
broker asks just before its conditional write — so a retry made after the run
moved to another member never takes back what that member holds, and one that
finds its takeover ended while it ran lets go of what it took. While it
lasts, the run's event history has a `lease_takeover` row saying so,
`cloop hub doctor` and Settings → Hub health warn `runs.lease_takeovers`, and
`cloop_lease_takeovers_total` counts the attempts. Once taken over, a second
row says so and what the lease feeds is restored. One still undecided when it
lapses, or when the run ends, is recorded on the run as failed, and the run
carries on without it. Before, the adopter printed one line on stderr and
rewrote the owner row without it: nobody extended the lease, the janitor
retired it at its TTL, and the run's next push or kubectl call failed with
nothing on the run saying why.
A cluster of one is the same: a hub restarted in its own directory adopts the
runs its previous process left, by the same rows. See [a hub restarted
mid-run](executors.md#the-project-comes-back-task-20339) and
[the git proxy's account](git-proxy.md#a-hub-restarted-mid-run).

Executor health probes are divided the same way: an agent is probed by the
member holding its connection, every other executor by the leader, so an
executor is never marked offline by a member that simply cannot see it.

---

## A member that stops answering

A heartbeat proves one goroutine and one database write. A member can keep both
going while everything that serves requests is stuck — a deadlock in a handler,
a listener that stopped accepting, an advertise address that leads nowhere —
and until Task 20419 such a member was as alive as any other: requests
forwarded to it waited on it without bound, and its runs were never adopted.

Each member now asks every live peer, every 5 seconds, whether it answers: a
signed `GET /api/internal/cluster/ping` over the [peer channel](#the-peer-channel),
bounded at 5 seconds. A peer that has failed every probe for the member TTL (20
seconds), and at least twice, is **unresponsive** to that member, which from
then on treats it as down for everything that hands work over:

- what it owns — runs, agent sockets, in-flight logins and conversations — is
  adoptable, and adopted by the member that would adopt it from a member that
  died;
- nothing more is forwarded to it, and the requests already waiting on it fail
  at once with a `502` that says it is not answering;
- its handle rows and its host-process lease directories are a stopped
  member's.

If the leader itself stops answering it keeps its lease, which is renewed in
the database, so the member serving longest adopts in its stead. The verdict is
each member's own and is cleared by the first answer; adoption is a
compare-and-swap on the owner row, so two members judging differently still
produce one adopter, and a member judged wrongly — slow rather than stuck —
finds its run adopted at its next ownership check and lets it go, as a member
paused past its heartbeat TTL does. `GET /api/cluster` lists such a member as
`alive` with `unresponsive` set.

A request a member accepted and never answers is also bounded on its own: a
forwarded request waits at most 6 minutes for the owner's response headers —
longer than the slowest request a member answers only once its work is done, a
voice transcription or an agent's `cloop init`, each bounded at 5 minutes — and
then fails with a `502`. Once the headers arrive, a response streams for as long
as it lasts.

---

## Revoking what a dead member held

A run's secret lease is held by one member: the one that dispatched or adopted
the run, which keeps it alive and releases it. When that member dies the lease
is held by nobody until another member adopts the run — and revoking it in that
window used to answer `404 no lease with that id is open`, record nothing, and
let the adopter take the lease over and restore the git proxy and Kubernetes
monitor sessions it fed. An incident responder's revoke was undone without a
trace. Since Task 20419:

- **A lease revocation is recorded** in `secret_lease_revocations` before any
  holder is asked, and outlives the lease record. The broker refuses to hand a
  revoked lease to a new holder, so the member adopting the run takes the
  material back from the workload instead — closing nothing it would have
  restored, because it restores nothing — and retires the lease's record. It
  also refuses to extend one, so a live holder the revocation could not reach
  lets the lease lapse, and its own lease janitor takes it back within a pass.
- **The answer is `202`, not `404`,** when nothing reachable holds the lease
  because its member is gone: the revocation is recorded, and each holder it
  waits for is listed under `pending` with when it takes effect — when that
  member's run is reached. A member the revocation could not ask, which in the
  seconds after a death is usually a member not yet judged dead, is listed
  there too, as `hub member <id>`, rather than as an `unreachable` holder. The
  record binds it either way: if it is still running, its own lease janitor
  takes the credential back, and if it stopped, so does the member that adopts
  its run. `200` still means every holder answered.
- **The member that adopts a dead member's runs reaches them now**, rather than
  at its next sweep: a revocation — of a lease, of a grant, of a lapsed lease —
  that concerns a lease a dead member held has that member's run adopted first
  by the member that would adopt it (the leader for a container, Pod or host
  process; the member holding an agent's socket for the agent's), and the
  leader also rehydrates the dead member's handle rows into its own drivers, so
  a container or Pod whose run cannot be adopted at all — its claim was never
  recorded — is reached through its executor all the same. What adoption took
  back is reported as the revocation's.
- **A grant revocation reports such a lease honestly.** The cascade used to
  skip leases "held by nobody here", so it reported `revoked` while a dead
  member's container still held the material; the leader now lists the lease
  as `pending` until its workload is reached.
- **Host-process lease directories go when their member does.** A member that
  sees another die wipes the directories that member materialised in
  `/dev/shm` on this machine; one not visible from here (another machine,
  another mount namespace) is left on record for a process that can see it.
- **A cordon whose agent's member cannot be asked** — dead and not yet judged
  so — records each lease issued to the agent revoked and revokes it from the
  member that cordoned, rather than logging the failure.

A revocation stays pending until a process finds the material gone from every
holder; the lease janitor retries pending ones, backing off to every half hour,
and the leader prunes enforced ones after 30 days.

---

## No run goes unsupervised

A dispatch is on record before its workload exists (Task 20419). The member
writes a **dispatch intent** — the run id, the executor, itself, the run's
leases — to `dispatch_intents` before it asks the executor for anything, and
marks the project's run claim with the run id; it completes the intent with the
workload's handle; and it retires it once the run is on record, or when the
workload ends. Every step of becoming supervised must succeed:

- an intent, a session record (`executor_sessions`, which failover reads) or
  the run's owner row that cannot be written **refuses the dispatch**: the
  workload, if it already exists, is stopped, its lease released, its egress
  session closed, and `POST /api/run` answers `503` with the storage error. It
  used to proceed untracked — never failed over, never adopted, its
  credentials never taken back after its member died;
- an intent whose member died names a workload no member supervises. The
  member that would have adopted its run stops it — through the handle its
  driver recorded, rehydrated from the dead member's row, or by its run id (a
  container's `cloop.spec.run_id` label, a Pod's `cloop.dev/run-id`) — takes
  its leases back and retires their records, and only then does the leader
  clear the dead member's claim. A claim whose dispatch reached its executor
  holds its project for the orphan grace meanwhile, so the project cannot be
  started again beside the workload.

An intent whose run turns out to be on record after all — the member died
between recording the run and retiring the intent — is retired and the run left
to adoption.

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
- **Host-executor runs outlive a killed member without their credentials**, as
  described [above](#runs-agents-and-failover): the process carries on, its
  lease directory is wiped, and only a member in its pid namespace can watch it.
  Use an isolating executor for runs that must survive a member intact.
- **Credentials minted by a member that dies** are restored by the member that
  adopts their run when they stand on the run's lease or belong to the run — its
  git proxy, Kubernetes monitor and egress sessions (Task 20383), and since Task
  20390 a device workspace's pinned session, whose workspace lease the run's
  owner row names — unless the lease was revoked meanwhile: then nothing is
  restored and the material is taken back
  ([Revoking what a dead member held](#revoking-what-a-dead-member-held)). A request made before the adoption waits up to 60 seconds
  for it. A restored git or Kubernetes session is served by its adopter and a
  request reaching another member is forwarded there, so the proxies'
  `advertise_url` has to reach some live member — a load balancer, or one
  address a restarted process binds again. Egress is not forwarded: a restored
  egress session is served by the adopter's own listener, so the egress
  `advertise_addr` has to reach the adopter, which on a single hub is the
  address the restarted process binds again. A run that moves between two live
  members keeps its egress session on the member that served it, until the run
  ends or that member stops and the run's owner takes it over (Task 20451).
- **A takeover the store cannot decide** is retried by the adopter until its
  credential's recorded expiry (Task 20451, [above](#runs-agents-and-failover));
  for that long what the credential feeds is not served — the request that
  needs it waits up to 60 seconds, as before an adoption — and a fault that
  outlasts the lease costs the run its credentials, recorded on its history as
  a failed takeover.
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
  died gets a 401. It is a residual risk of the
  [security model](../security/model.md#what-is-not-mitigated), pinned by
  `TestAPodsWorkspaceSourceKeepsNoLeaseRecords`.
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
- [`pkg/ui/run_supervision_test.go`](../../pkg/ui/run_supervision_test.go) and
  [`run_supervision_cluster_test.go`](../../pkg/ui/run_supervision_cluster_test.go)
  — a dead holder's lease revoked (`202`, recorded) and taken back on adoption
  instead of taken over; a dispatch whose session record the database refuses
  (`PRAGMA query_only`) refused and its workload stopped; a dead member's
  unrecorded dispatch reaped before its claim is cleared; a member that
  heartbeats without answering having its run adopted; a dead member's host
  lease directory wiped before its record goes; a workload row adopted by one
  member.
- [`pkg/hubcluster/probe_test.go`](../../pkg/hubcluster/probe_test.go) — a
  forward to a member that never answers bounded by the header timeout; a
  member that heartbeats but does not answer judged unresponsive, its requests
  failed, what it owns orphaned; an unresponsive leader's adoption done in its
  stead.
- [`tests/cluster`](../../tests/cluster/cluster_test.go) — three real `cloop ui`
  processes behind a load balancer with an enrolled edge agent: a run started on
  one member is dispatched by the agent's member and watched from the third; its
  member is SIGKILLed and a survivor adopts the run without restarting it; Stop
  pressed on a member not streaming a run reaches the one that is; a SIGTERM
  hands a run over, and each run gives its tenant's concurrency slot back on the
  member that settles it. Along the way it scrapes every member's `/metrics`: the
  gauges read from the shared database come from the leader alone, before and
  after a member dies, and the run's start, completion and cancellation are each
  counted once across the cluster. It runs in CI as the `hub-cluster` job,
  against a binary built with the race detector.
- [`pkg/ui/takeover_retry_test.go`](../../pkg/ui/takeover_retry_test.go) — a
  lease whose takeover a locked store refuses a few times, kept on the owner
  row as undecided and held once the store answers, its git and Kubernetes
  sessions served again and a push landing; the same for a workspace lease; one
  the store refuses past the lease's expiry, or past its run, recorded on the
  run as failed; and both halves of a run moving between two live members — the
  adopter keeping the egress session named and taking it over when its holder
  stops, the holder ending it when the run ends.
- [`tests/e2e/hubrestart_takeover_test.go`](../../tests/e2e/hubrestart_takeover_test.go)
  — a real hub SIGKILLed mid-run with its lease's record made unreadable, the
  restarted process warning `runs.lease_takeovers`, counting retries, and
  taking the lease over once the record is repaired; the run settles as the
  other restart scenarios do.
- [`tests/cluster/revocation_test.go`](../../tests/cluster/revocation_test.go)
  — two real members; the one holding a run's lease is SIGKILLed and the lease,
  then its grant, are revoked through the survivor. For a container run the
  credential is gone from the sandbox and its staged copy from the host, and
  the lease is never restored on adoption; for a host-process run the dead
  member's `/dev/shm` directory is wiped while the reparented process runs on.
  In the `hub-cluster` job.
- The chart job in CI installs the Helm chart into a kind cluster, scales it to
  three replicas, and asserts one cluster with one leader on one node — before
  and after a rolling restart that replaces every member.
