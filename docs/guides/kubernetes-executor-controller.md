# Kubernetes executor controller

An executor pool runs your projects' tasks in Pods on a Kubernetes cluster that
you operate. You install the executor controller in the cluster with a Helm
chart. The controller keeps a connection open to the hub and watches how many
runs are waiting for its pool. For each waiting run it starts a runner Pod. A
runner enrolls with the hub, takes one run and exits, and the controller
deletes it. When nothing is waiting, the controller retires the runners that
are left over.

The controller and its runners connect out to the hub over HTTPS. The hub
never connects into the cluster and holds no credential for it.

- [Which Kubernetes executor to use](#which-kubernetes-executor-to-use)
- [How a run reaches a runner](#how-a-run-reaches-a-runner)
- [Before you start](#before-you-start)
- [Create a pool and install its controller](#create-a-pool-and-install-its-controller)
- [Bind projects to the pool](#bind-projects-to-the-pool)
- [What runner Pods are made of](#what-runner-pods-are-made-of)
- [Keep a volume per project](#keep-a-volume-per-project)
- [Scaling](#scaling)
- [Rotating the controller's credential](#rotating-the-controllers-credential)
- [Upgrading](#upgrading)
- [Troubleshooting](#troubleshooting)
- [Removing a pool](#removing-a-pool)
- [How this is tested](#how-this-is-tested)

The [executor architecture](../architecture/executors.md#executor-pools)
describes the design, and the
[threat model](../security/threat-model.md#cross-cutting-executor-pools) says
what a compromised controller or cluster can and cannot do.

## Which Kubernetes executor to use

cloop can run work on Kubernetes in two ways:

- **The hub's Kubernetes executor**, configured under `executors.kubernetes`
  in the hub's configuration. The hub holds a kubeconfig, or its own
  ServiceAccount token when it runs in the cluster, and creates one Pod per run
  through the cluster's API server.
- **An executor pool**, served by the executor controller. The controller runs
  inside the cluster with a Role in one namespace and asks the hub for work.
  The hub keeps the pool's definition and a hash of the controller's
  credential.

| | The hub's Kubernetes executor | An executor pool |
| --- | --- | --- |
| Who calls the API server | the hub | the controller, inside the cluster |
| Network path | the hub reaches the API server | Pods in the cluster reach the hub over HTTPS |
| What the hub holds for the cluster | a kubeconfig, or its own ServiceAccount token | nothing |
| What a run is | a Pod the hub creates for the run | a runner Pod running the cloop agent, which takes one run the way an enrolled machine does |
| How fast a run starts | each run waits for its Pod to be scheduled | runners can wait ready ahead of demand (`minRunners`) |
| A project's checkout and caches | fetched again for every run | optionally kept on a volume per project |
| Network policy | a NetworkPolicy per Pod (`egress_filter`) | one NetworkPolicy for every runner in the namespace, set in the chart |
| Dashboard model calls (Split, Revise, blocker analysis, plan chat) | run on the executor | refused with `waiting_for_pool_capacity`, because a runner takes only queued runs |

Use the hub's executor when the hub runs in the cluster or can reach its API
server, and you are content for the hub to hold a credential there. Use a pool
when:

- the cluster belongs to another team, or to a customer who will not give the
  hub a kubeconfig;
- the cluster accepts no inbound connections from where the hub runs;
- runs should start without waiting for a Pod to be scheduled, or a project
  should keep its checkout and package caches between runs;
- several clusters, each looked after by its own owner, should serve one hub.

One hub can use both. Each project is bound to one executor or one pool.

## How a run reaches a runner

1. You bind a project to the pool. Its executor binding becomes `pool:<id>`.
2. Someone starts a run. The hub checks them against the pool's access list
   and queues the run. Until a runner takes it, the project shows as paused
   with the reason `pool_capacity`.
3. The controller reads the pool's demand from the hub and starts a runner Pod.
   The hub mints a single-use runner token for it, which the controller writes
   to a Secret that the Pod owns.
4. The runner enrolls with that token. The hub hands it the oldest queued run
   it may take, and starts the run on it on behalf of the person who started it.
5. From here the run works like a run on an enrolled machine: the same secret
   leases, credential guards, write-back of the run's commits, and failover.
6. When the run is settled, the hub retires the runner and the runner exits.
   The controller then deletes the Pod and its Secret.

The [executor architecture](../architecture/executors.md#a-runners-life) draws
these steps as a diagram.

## Before you start

You need:

- **Kubernetes 1.27 or later.** The ExecutorPool resource checks its fields
  with CEL functions that 1.27 introduced.
- **`kubectl` and `helm` 3** on a machine that reaches the cluster, with the
  rights to create a namespace, a Role, a RoleBinding and the ExecutorPool
  CustomResourceDefinition. A CustomResourceDefinition is cluster-wide, so
  installing it usually needs a cluster administrator.
- **A hub served over HTTPS** at an address that Pods in the cluster can reach.
  If the hub serves TLS itself (`ui.tls`), the controller pins the hub's key.
  Behind a proxy that terminates TLS, the controller trusts the system
  certificate store, or the CA certificates you give it.
- **`executor.manage` on the hub.** On a hub with single sign-on, creating,
  changing and revoking a pool also needs a recent sign-in.
- **A namespace for the controller alone.** The controller's Role can read
  every Secret in its namespace, and anyone who may write ExecutorPools there
  can have it start Pods.

Every project that runs on the pool also needs a Claude or Copilot credential
granted to it, as on any executor that isolates. See
[the Claude credential of a sandboxed run](secrets.md#the-claude-credential-of-a-sandboxed-run).
A pool queues a run first and checks the credential when it hands the run to a
runner, so a project without one has its run fail at that point, with
`harness_credential_missing`. The runner then waits for the next run.

## Create a pool and install its controller

Creating a pool on the hub also mints the controller's first credential, and
prints the commands that install the controller with it. The credential is
shown once and cannot be recovered.

### From the dashboard

Open **Executors** and click **+ Add Kubernetes pool**. The dialog asks for:

- **Name**: lowercase letters, digits and dashes. It names the pool on the hub,
  the ExecutorPool object and, by default, the Helm release.
- **Max runners**: the most runners the pool may have at once. The hub mints no
  runner beyond it.
- **Labels** (optional): the labels the pool's runners enroll with. A secret
  granted to `label:gpu=true` reaches the runners of a pool labelled
  `gpu=true`.
- **Who may run work on it** (optional): users, groups or roles, such as
  `group:ml-team, user:alice@example.com`. Leave it empty to let any project
  bound to the pool run there.
- **Kubernetes namespace** (optional): `cloop-<name>` unless you choose one.
- **Keep a volume per project**: see
  [Keep a volume per project](#keep-a-volume-per-project). When you tick it,
  the dialog also asks for the volume size, the storage class, and what to do
  with volumes the pool no longer needs.

Click **Create pool**. The dialog then names the pool's binding, `pool:<id>`,
and shows the commands to run where `kubectl` and `helm` reach the cluster,
with the hub's URL, its pin and the new credential filled in. **Copy commands**
copies them.

If you opened the dashboard over plain HTTP, the dialog shows the credential
but no commands, because the controller only connects to a hub over HTTPS.
Serve the hub over HTTPS, mint a credential there with
`cloop executor pool rotate-credential <pool>`, which prints the command that
stores it in a Secret, and then run the `helm install` shown in
[What the commands do](#what-the-commands-do) with your hub's URL and its pin
(`cloop hub pin` prints the pin).

### From the CLI

`cloop executor pool create` makes the same request and prints the same
commands:

```bash
cloop executor pool create gpu --max-runners 4 --label gpu=true \
  --audience group:ml-team --persistence --size 50Gi --storage-class fast-ssd
```

It takes `--min-runners`, `--namespace`, `--release`, `--owner`, `--harness`
and `--reclaim-policy` too, and like every `cloop executor pool` command it
uses the session `cloop login` stored, or `--hub` and `--token`. The
[command reference](../reference/commands.md#cloop-executor-pool) lists its
flags. The last line of its output names the binding to use for the pool,
`pool:<id>`.

### What the commands do

For the pool above, on a hub at `cloop.example.com`, the commands look like
this:

```bash
kubectl apply --server-side -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: cloop-gpu
  labels:
    pod-security.kubernetes.io/enforce: restricted
EOF
kubectl -n cloop-gpu create secret generic gpu-pool-credential \
  --from-literal=credential='cloop_pool1_…' \
  --dry-run=client -o yaml | kubectl apply --server-side --force-conflicts -f -
helm install gpu https://cloop.example.com/charts/cloop-executor-controller.tgz \
  -n cloop-gpu \
  --set pool.create=true \
  --set-string pool.name=gpu \
  --set-string pool.hubURL=https://cloop.example.com \
  --set-string pool.hubCAPin=sha256:Vb9mR0E2Xj3LwJ8kq1yZ5nH7tC4uA6dF0gS2pQ9rT3w= \
  --set-string pool.credential.existingSecret=gpu-pool-credential \
  --set pool.maxRunners=4 \
  --set pool.persistence.enabled=true \
  --set-string pool.persistence.size=50Gi \
  --set-string pool.persistence.storageClassName=fast-ssd \
  --set-string image.tag=edge
```

1. The first command creates the namespace and holds it to the restricted Pod
   Security profile. The label is part of the applied manifest, so if another
   tool already labels the namespace differently, the command fails with a
   conflict instead of relabelling it.
2. The second stores the credential in a Secret. It is applied server-side,
   because a client-side `kubectl apply` would copy the whole Secret,
   credential included, into its `last-applied-configuration` annotation. The
   credential never goes on the `helm` command line either: Helm keeps `--set`
   values in the release's stored manifest.
3. The third installs the chart from the hub. The hub serves its own build's
   chart at `/charts/cloop-executor-controller.tgz`, so the chart always
   matches the hub. The chart creates an ExecutorPool from the `pool.*`
   values. On a hub that runs a release, `image.tag` is that release; on any
   other build it is `edge`, the newest build of `main`. To fix the controller
   image to one build, add `--set image.digest=sha256:…`.

You can run the first two commands again safely. The last one is
`helm install`, which refuses to overwrite an existing release.
`helm upgrade --install` would replace the release's values without saying so.

If the machine running `helm` does not trust the hub's certificate, add
`--ca-file <the CA's PEM file>` to `helm install`, and give the controller the
same file with `--set-file pool.hubCABundle=<the CA's PEM file>`. When
`pool.hubCABundle` is set, the controller trusts those certificates and
nothing else for the hub. Runners trust them in addition to the system store;
on a hub that serves TLS itself, the pin holds both to the hub's key.

Two protections are off in the chart by default, and the commands do not turn
them on. Turn them on in production: `networkPolicy.enabled`, once runs can
reach the model API through the hub (see
[What runner Pods are made of](#what-runner-pods-are-made-of)), and
`requireDigest`, which refuses to render unless every image the release names
is pinned by digest.

### Check that it came up

```bash
kubectl -n cloop-gpu rollout status deploy/gpu-cloop-executor-controller
kubectl -n cloop-gpu get lease cloop-executor-controller -o jsonpath='{.spec.holderIdentity}{"\n"}'
kubectl -n cloop-gpu get xpool
```

The chart runs two replicas of the controller. A Lease elects the one that
starts and stops runners, and the other takes over within a lease period if the
leader goes away. A replica reports ready once it has listed and is watching
everything its Role covers, so a Pod that never becomes ready usually means a
missing RBAC rule.

`xpool` is the short name for `executorpools`:

```console
$ kubectl -n cloop-gpu get xpool
NAME   DESIRED   RUNNERS   BUSY   IDLE   QUEUED   READY   AGE
gpu    0         0         0      0      0        True    2m
```

`READY` turns `True` once the controller has the pool's demand from the hub and
nothing is wrong. `-o wide` adds the number of volumes. On the hub,
`cloop executor pool show gpu` shows the controller's build and protocol and
when it last made contact, and the pool's card on the Executors tab shows the
same.

## Bind projects to the pool

On a project's **Overview**, click the **Executor** card and choose the pool
under **Executor pools**. Binding a project needs `executor.manage`. Over the
HTTP API it is `POST /api/projects/{idx}/executor` with
`{"executor_id": "pool:<id>"}`.

The hub refuses the binding with `409` when the pool's runners cannot meet the
project's requirements, for example a project whose `.cloop/sandbox.yaml` asks
for a hypervisor that the pool's runners do not declare.

When someone starts a run, the hub checks:

- that the person is on the pool's access list, if it has one;
- that the pool's owner, if it has one, may read the project;
- that the pool's runners meet the run's requirements, with the same rules the
  scheduler applies to any executor.

A run that passes is queued. A run that can never be handed to a runner, for
instance because the project was bound elsewhere or the access list changed,
leaves the queue, and the project says why.

A pool's runners never appear as executors you can bind to, and a run never
goes to one by name. Runs reach runners only through the pool's queue, which
is what holds them to the access list.

## What runner Pods are made of

The ExecutorPool's `spec.template` shapes the runner Pods: the image,
RuntimeClass, resources, placement, ServiceAccount, and variables taken from
Secrets. The chart's `pool.template.*` values set the same fields. Here is a
pool like the one above, written by hand with more of the template filled in,
as you would write it with the chart's `pool.create` left off:

```yaml
apiVersion: cloop.dev/v1alpha1
kind: ExecutorPool
metadata:
  name: gpu
  namespace: cloop-gpu
spec:
  hubURL: https://cloop.example.com
  hubCAPin: sha256:Vb9mR0E2Xj3LwJ8kq1yZ5nH7tC4uA6dF0gS2pQ9rT3w=
  poolCredentialSecretRef:
    name: gpu-pool-credential
    key: credential
  minRunners: 1
  maxRunners: 4
  scaleDownDelay: 10m
  runnerLabels:
    team: ml
  template:
    runtimeClassName: gvisor
    serviceAccountName: gpu-cloop-executor-controller-runner
    resources:
      requests: {cpu: "2", memory: 4Gi}
      limits: {cpu: "4", memory: 8Gi, ephemeral-storage: 20Gi}
    nodeSelector:
      pool.example.com/cloop: "true"
    tolerations:
      - key: dedicated
        operator: Equal
        value: cloop
        effect: NoSchedule
    env:
      - name: HTTPS_PROXY
        secretKeyRef: {name: runner-proxy, key: url}
```

`cloop executor controller crd` prints the definition with every field and its
rules. A pool whose spec breaks a rule shows `Invalid` with every problem named,
and the controller starts nothing for it.

**What you choose.** `image` is cloop's signed harness image when you leave it
empty, at the controller's own tag: its release's, or `edge` for a controller
built from `main`. The controller resolves that tag to a digest at the
registry, verifies the signature, and the runner Pods name the digest. Another
image is used as written. It needs `cloop` on its `PATH`, `git`, a CA bundle and the harness
your projects use, and it runs as UID 65532. `runtimeClassName` puts runners
under gVisor or Kata. `env` entries are references to Secrets only: the
controller never reads their values, and `HOME`, `PATH` and `CLOOP_*` are
reserved for the controller.

**What the controller decides, whatever the template says.** Every runner Pod
meets the restricted Pod Security Standard: it runs as a non-root UID and GID,
drops every capability, uses `seccompProfile: RuntimeDefault`, allows no
privilege escalation and has a read-only root filesystem. It uses no host
namespaces or host paths and does not restart, because a restarted runner
would try to redeem a token it already spent. Its ServiceAccount token is not
mounted unless the template sets `automountServiceAccountToken: true`, which a
pool may do only together with a `serviceAccountName` other than `default`.
The token gives a run's code that account's authority, so bind the account to
exactly what the runs need. A pool whose runners would run as the controller's
own ServiceAccount is `Invalid`.

**Where a run executes.** The run is a child process of the agent, inside the
runner container. The runner Pod is the sandbox, which is why the template's
RuntimeClass matters: it decides whether that sandbox has a kernel of its own.

**Network.** The chart's `networkPolicy` values, off by default, add a
NetworkPolicy that limits every runner in the namespace to the hub and DNS and
refuses every connection to them. A run then reaches only DNS and the hub: its
git proxy for repositories, its model relay for model calls, and its egress
proxy for whatever an egress grant allows. The harness calls the model API
directly unless the hub's model relay is on, so turn the relay on, or grant the
runs egress to the model API's host, before you enable the policy, or every
run fails at its first model call. Set `networkPolicy.hub` to select the hub's
Pods or its address, and add the egress proxy's port and the Kubernetes
monitor's to `networkPolicy.hub.ports` if runs use those grants. A
NetworkPolicy is enforced by the cluster's network plugin. Calico, Cilium and most managed plugins
enforce it; flannel and kindnet accept the object and ignore it.

**Images by digest.** Start the controller with `--require-image-digest` (the
chart's `requireDigest: true` sets it) to refuse any pool whose runner image is
named by tag, except cloop's own images, which the controller resolves and
verifies anyway. `controller.imageProvenance: required` refuses a cloop image
whose signature cannot be checked; the default, `warn`, runs it with a warning
Event on the pool. A signature that is present and wrong is refused either
way.

## Keep a volume per project

A runner normally starts with nothing: it clones the project, downloads its
dependencies and builds from scratch, and all of that goes when the Pod exits.
With persistence on, the controller gives runners PersistentVolumeClaims that
outlive them. A project's next run then finds its checkout, its git objects and
its package caches where the last run left them, fetches the new commits and
builds from a warm cache.

Turn it on with **Keep a volume per project** in the dashboard's dialog,
`--persistence` on `cloop executor pool create`, the chart's
`pool.persistence.*` values, or `spec.persistence` on the ExecutorPool:

```yaml
spec:
  persistence:
    enabled: true
    size: 50Gi                    # required
    storageClassName: fast-ssd    # empty: the cluster's default class
    accessModes: [ReadWriteOncePod]   # default: ReadWriteOnce
    mounts: [workspace, gitCache, toolCache]   # default: all three
    reclaimPolicy: Retain         # default: Delete
    maxClaims: 8                  # default: maxRunners
    minFree: 2Gi                  # default: 1Gi
```

### What is kept, and what is not

| `mounts` entry | Directory on the volume | What it keeps |
| --- | --- | --- |
| `workspace` | `workspace/` | the project's checkout |
| `gitCache` | `git/` | a bare repository per upstream, which a fresh checkout takes its objects from |
| `toolCache` | `tools/` | the Go module and build caches, and the npm, Yarn, pip and uv caches |

These never go on a volume:

- the harness's home directory, with its login and transcripts;
- leased credential files and git credentials;
- the runner's own token and configuration;
- caches that build tools also keep logins in: `XDG_CACHE_HOME`,
  `GRADLE_USER_HOME`, `CARGO_HOME` and `RUSTUP_HOME`;
- `/tmp`, and anything else outside the three directories above.

Homes, leased files and git credentials live on a memory-backed `emptyDir` of
at most 512 MiB, which counts against the Pod's memory. The caches that can
hold a login go to the Pod's own scratch space and are removed with the Pod.
The agent refuses to start with its homes or its lease directory inside the
workspace root it keeps on the volume.

What a run writes into its own checkout or a package cache stays there for the
project's next run. A token a build writes into the project's `.npmrc`, for
example, is the project's content and stays on its volume.

A runner does not trust a checkout it finds on its volume. It runs no hooks and
no file-system monitor from it, and rewrites the repository's git configuration
to the settings cloop sets before git reads it. After the fetch, it checks that
every object the commit needs is present and intact, resets the tree to the
commit, removes untracked files (ignored files such as `node_modules` stay),
and compares the result with what the hub sent. If any of that fails, it
clones afresh. The hub's write-back remains the record of what a run produced.

### One project per volume

A volume never carries one project's data into another project's run:

- Each claim records whose data it holds in its `cloop.dev/holds` annotation
  and `cloop.dev/project` label: a digest of the hub's pool, the project and
  the project's owner, never a path. `cloop.dev/project-name` and
  `cloop.dev/project-owner` name the project for people reading the claim.
- When a project's run is waiting and a volume holding that project's data is
  free, the controller starts the runner on it and the runner is minted as
  holding that project. The hub hands such a runner only that project's runs,
  and only for people who may still read the project. The runner checks it
  too, and refuses a run of any other project.
- Every other runner starts on a new volume, or on one that an init container
  (`cloop executor runner-storage`) empties before the runner starts. That
  includes a volume whose last runner never reported which project it ran.
  The controller prefers a new volume, while it has room for one, to emptying
  another project's.
- While any hub member runs a build too old to keep projects' volumes apart,
  every runner starts on an emptied volume.

Everyone who may run a project shares what its earlier runs left on its volume,
whoever started them: files a build wrote to ignored paths, downloaded
dependencies, build caches.

### Volumes and idle runners

A kept volume helps only when a project's run gets a runner started for it.
The idle runners that `minRunners` keeps hold nothing, and the hub hands a
waiting run to one of them straight away, unless a runner holding that
project's volume is idle too. Such a run starts on a fresh or emptied volume
and fetches everything again. Each idle runner the controller starts after
that needs a volume holding nothing, and once the pool has `maxClaims` volumes
it empties the one least recently used.

So choose between the two. With `minRunners: 0`, every run waits for a Pod to
start, and the controller puts it on its project's own volume when one is free.
With idle runners, runs start at once and mostly cold. Raising `maxClaims`
above `maxRunners` keeps more projects' volumes before any is emptied.

One volume is mounted by one runner Pod at a time. The controller marks a claim
as taken in its `cloop.dev/claimed-by` annotation, guarded by the claim's
`resourceVersion`, so two controller replicas that both see the volume free
cannot both take it. It releases the claim only after the Pod that held it has
terminated. Do not delete runner Pods with `--force`: the controller releases a
volume as soon as the Pod object holding it is gone and the claim is at least
three minutes old, while a force-deleted Pod's containers can still be running
on its node. With `ReadWriteOnce`, a new runner on the same
node could then mount the volume beside them; `ReadWriteOncePod` prevents that
on storage drivers that support it.

### Size, free space and storage classes

`size` is each claim's request. A changed `size` applies to claims created
after the change; the controller does not resize existing claims.

Before each runner starts, the init container holds its volume to `minFree`,
1 GiB unless you set it. Below that it clears the caches first, then the
workspace. A volume that is still below `minFree` when empty is reported full
(`StorageFull`) and left alone for ten minutes, and runners start on other
volumes while there are any.

`maxClaims`, which defaults to `maxRunners` and may not be lower, bounds how
many volumes the pool keeps. More volumes keep more projects' workspaces warm.
Claims are named `<pool>-storage-0`, `<pool>-storage-1` and so on, and carry
the label `cloop.dev/executor-pool=<pool>`:

```bash
kubectl -n cloop-gpu get pvc -l cloop.dev/executor-pool=gpu \
  -L cloop.dev/project -o wide
```

With a storage class whose binding mode is `WaitForFirstConsumer`, a new claim
stays `Pending` until a runner Pod that mounts it is scheduled. That is normal.
The controller reports a volume as stuck only when the scheduler says the
volume is what keeps the runner Pod from being placed.

### When the pool no longer needs a volume

`reclaimPolicy` decides what happens to claims past `maxClaims`, to every claim
when you turn persistence off, and to every claim when you delete the
ExecutorPool:

- `Delete`, the default: the controller deletes claims it no longer needs. The
  ExecutorPool owns each claim, so deleting the pool deletes them all.
- `Retain`: claims are kept, with the record of whose data they hold. If the
  pool grows again, or you create it again with the same name for the same
  hub pool, a project's next run gets its own volume back unwiped.

Deleting a claim then follows the PersistentVolume's own reclaim policy, which
comes from the StorageClass. Under `Retain` the disk outlives the claim as
well.

Revoking a pool on the hub does not touch its volumes. The hub has no access to
the cluster, so whatever the volumes hold stays there until you delete it. See
[Removing a pool](#removing-a-pool).

## Scaling

Three numbers decide how many runners a pool has:

- **`minRunners`** on the ExecutorPool is the idle target: runners kept started
  beyond the demand, so a run does not wait for a Pod to start. `0` lets the
  pool scale to nothing. With volumes per project, idle runners work against
  reuse; see [Volumes and idle runners](#volumes-and-idle-runners).
- **`maxRunners`** on the ExecutorPool bounds the runners the controller
  starts.
- **`max_runners`** on the hub's pool bounds the runners the hub mints tokens
  for. It counts every unexpired runner token and every runner not yet
  retired, and is checked in the same database transaction that mints, so
  neither two controllers nor two hub members can exceed it.

The controller aims for `minRunners` plus the busy runners plus the queued
runs, never fewer than `minRunners`, and never more than the lower of the two
maxima. It starts at most ten runners per pass.

Set both maxima when you change one. `cloop executor pool update` changes the
hub's and prints the `helm upgrade` that changes the cluster's:

```bash
cloop executor pool update gpu --max-runners 8
helm upgrade gpu https://cloop.example.com/charts/cloop-executor-controller.tgz \
  -n cloop-gpu --reuse-values --set pool.maxRunners=8
```

A `spec.maxRunners` lower than the hub's `max_runners` stops the pool at the
lower one, and runs wait while the hub thinks there is room. After ten minutes
of that, hub doctor warns `executors.pools.capacity`.

**Scaling down.** When the pool has more runners than it wants, the controller
retires those that have been idle for `scaleDownDelay` (5 minutes by default,
between 0s and 24h). A runner takes only one run, so an idle runner is one that
has never had a run, and its idle time counts from when it enrolled. Runners
that hold a project's volume that no waiting run wants go first, and they go at
once, without the delay, when a waiting run has neither a runner nor room for
one.

The controller does not stop runners on its own judgement: it asks the hub to
retire them, and the hub decides from its own record. It retires a runner that
has not enrolled yet (and revokes its token), retires an idle runner only while
it is still idle, and never retires a busy one. The controller deletes a
runner's Pod once the runner has exited. Separately, the hub retires any runner
that has waited 15 minutes without being handed a run, so the idle runners
that `minRunners` keeps are replaced about every quarter of an hour.

**Cordoning.** `cloop executor pool cordon gpu --reason "node upgrades"` stops
the hub handing the pool's runners any queued run and tells the controller
there is no demand. Busy runners finish, idle ones are retired after
`scaleDownDelay`, and nothing new starts until you run
`cloop executor pool uncordon gpu`. Runs waiting for the pool say it is
cordoned.

**The cluster's own limits.** Give the namespace a ResourceQuota. When the API
server refuses a runner Pod, the controller records the refusal as a
`PodRefused` Event and condition, and asks the hub for no further runners in
that pass.

## Rotating the controller's credential

```bash
cloop executor pool rotate-credential gpu
```

This mints a new credential and prints the command that puts it into the
controller's Secret. The controller reads the Secret again within five
minutes, and at once when the hub refuses the credential it holds. The old
credential keeps working until you finish the rotation:

```bash
cloop executor pool rotate-credential gpu --finish
```

`--finish` revokes every older credential, but only once the newest has been
used more recently than any of them, and while no busy runner was started with
one of them. Revoking a credential retires the runners it started and revokes
the leases of their runs, so finishing early would cut runs short.
`--force` skips both checks.

`--namespace` and `--release` tell the command where the controller lives
when you installed it under names other than the defaults. If one hub pool is
served by controllers in two clusters, give each its own credential: a
controller gives back only the runners that its own credential minted.

## Upgrading

Upgrade the hub first, then each pool's controller. An older controller keeps
working against a newer hub, and hub doctor warns `executors.pools.protocol`
until you upgrade it. A controller newer than its hub can need something the
hub does not tell it yet. Against a hub that does not report its runners'
states, the pool shows `Degraded` with `HubTooOld` and the controller starts
and stops nothing; against one that cannot record which project a volume
holds, every runner starts on an emptied volume.

1. **Upgrade the hub**, as the [runbook](../operations/runbook.md#upgrade)
   describes. The upgraded hub serves the chart of its new build.
2. **Apply the CustomResourceDefinition.** Helm installs the chart's `crds/`
   on the first install and never again, so an upgrade of the release does not
   change the CRD. Apply it from a cloop binary of the new build, or from the
   chart the hub serves:

   ```bash
   cloop executor controller crd | kubectl apply -f -
   # or
   helm pull https://cloop.example.com/charts/cloop-executor-controller.tgz --untar
   kubectl apply -f cloop-executor-controller/crds/
   ```

3. **Upgrade the release** with the hub's chart and image. On a hub that runs a
   release, `cloop executor pool show <pool>` prints the command for a
   controller that is behind it, with the release's tag:

   ```bash
   helm upgrade gpu https://cloop.example.com/charts/cloop-executor-controller.tgz \
     -n cloop-gpu --reuse-values --set-string image.tag=0.0.8
   ```

   On a hub built from `main` the tag is `edge` before and after, so that
   command changes nothing, and a node keeps the `edge` image it already
   pulled. Upgrade an `edge` controller by its digest instead.
   `cloop hub verify-image` checks the image's signature and prints the digest
   its tag points at now:

   ```bash
   cloop hub verify-image ghcr.io/blechschmidt/cloop:edge
   helm upgrade gpu https://cloop.example.com/charts/cloop-executor-controller.tgz \
     -n cloop-gpu --reuse-values --set image.digest=sha256:…
   ```

The Deployment starts each new replica before it stops an old one. Runner Pods
belong to the ExecutorPool, not to the controller's Deployment, so runs in
progress carry on. The new leader rebuilds its view of the pool from the API
server and the hub, and starts no runner twice.

The default runner image is cloop's harness image at the controller's own tag,
so runners started after the upgrade use the new release's image, and runners
already running finish on theirs. On `edge`, the controller resolves the tag
again every ten minutes, so new runners follow `main` whatever build the
controller is. A runner image you named yourself stays as it is. It must carry
a cloop build that speaks the hub's agent protocol, so upgrade it with the
hub.

In production, pin the controller with `image.digest`, pin the runner image
with `pool.template.image` set to `repository@sha256:…` (or leave it empty for
the verified default), and set `requireDigest: true`.

## Troubleshooting

Start with the pool on both sides:

```bash
kubectl -n cloop-gpu describe xpool gpu      # conditions and Events
cloop executor pool show gpu                 # the hub's view, with a remedy for each problem
```

### By condition

An ExecutorPool has three conditions. `Invalid` is `True` when the spec breaks
a rule; its message names every problem, such as
`spec.hubURL: must be an https URL`. `Degraded` is `True` when something keeps
the controller from serving the pool, and `Ready` is `False` with the same
reason. `Ready` is `Unknown` with the reason `Connecting` until the hub first
answers, and `True` with the reason `Serving` when all is well.

| Reason | What it means | What to do |
| --- | --- | --- |
| `InvalidSpec` | The spec breaks a rule of the CRD, or a refusal of this controller's own: a runner that would run as the controller's ServiceAccount, or a runner image named by tag under `--require-image-digest`. Nothing is started | Fix the fields the message names |
| `HubUnavailable` | The controller cannot reach the hub, or the hub's certificate does not match `hubCAPin` or `hubCABundle` | Check that `hubURL` resolves and is reachable from the controller's namespace, and that the pin or CA bundle is the hub's current one |
| `HubRefused` | The hub refuses the credential: it was revoked, a rotation was finished, or the pool was revoked | Mint a new credential with `cloop executor pool rotate-credential` and put it in the Secret |
| `CredentialUnreadable` | The Secret or key that `poolCredentialSecretRef` names is missing or empty | Create the Secret, or correct its name or key |
| `HubTooOld` | The hub does not report its runners' states. The controller starts and stops nothing | Upgrade the hub |
| `DuplicatePool` | Another ExecutorPool already serves the same hub pool. One hub pool takes one ExecutorPool, or each would retire the other's runners | Delete one of them |
| `ImageUnresolved` | The default runner image, or one of cloop's own images named by tag, could not be resolved to a digest or verified. No runner starts | Let the controller reach the registry, or set `spec.template.image` to a digest |
| `RunnersRefused` | The hub refused to mint runners: the pool is at its `max_runners`, cordoned, or revoked | See the Event's message; raise `max_runners` or uncordon the pool if that is what you want |
| `PodRefused` | The API server refused a runner Pod: a ResourceQuota, an admission policy, the namespace's Pod Security level | Read the Event, which quotes the API server |
| `StoragePending` | A runner could not start on its volume: the claim stays `Pending`, or the scheduler cannot place the Pod with it | `kubectl describe pvc`: a storage class that does not exist or cannot provision, or a quota |
| `StorageFull` | A volume is below `minFree` even after it was cleared. It keeps its slot, is left alone for ten minutes and is then tried again | Expand the claim, if its storage class allows, or delete it once no runner holds it; a new one is made at the current `size`. Or lower `minFree` |
| `StoragePrepareFailed` | The init container that prepares a volume failed | The condition and the Event quote what the init container reported; the runner Pod is deleted once its volume is released |
| `StorageUnavailable` | No volume can be given to a runner that needs one, so it is not started: volumes that failed are being left alone and no other is free, or the API server refused a new claim (the Event for that is `PodRefused`) | Deal with the failed volumes (the reasons above), or with what refused the claim, such as a quota on PersistentVolumeClaims |
| `VolumeUnusable` | A volume is `Lost`, or three runners in a row failed on it, and the pool keeps it under `reclaimPolicy: Retain`. Runners use the other volumes | Delete the claim to free its slot |

Some reasons appear only as Events: `ScaledUp`, `ScaledDown`,
`OrphanCollected` (the controller removed a Pod or Secret left without its
other half, or gave back a runner it had minted but never started),
`RetireRefused` (the hub did not retire idle runners), `RunnerFailed` (a runner
Pod ended in failure; the Event quotes its retirement report),
`ImageUnverified` (a cloop image whose signature could not be checked runs
with a warning), `StorageUnsupported` (the hub cannot record which project a
volume holds, so every runner starts on an emptied volume), `StorageConflict`
(the hub handed a runner a run of another project than the one its volume
held, so the volume is emptied before it is used again), `VolumeCreated`,
`VolumeDeleted` and `VolumeRetained`. The controller records
the same Event for the same pool at most once every ten minutes.

When failed volumes leave no volume free for a runner, the controller also
tells the hub, and the runs waiting in the pool's queue show its message.

### By hub doctor finding

`cloop hub doctor`, Settings → Hub health, the pool's card on the Executors
tab, and `cloop executor pool list` and `show` all report the same problems.
The [runbook](../operations/runbook.md#doctor-executors) lists every doctor
check.

| Finding | Severity | What it means | What to do |
| --- | --- | --- | --- |
| `executors.pools.contact` | fail | Runs are waiting and no controller is in contact: the pool has no live credential, no controller ever used one, or none has been used for ten minutes | Install the controller with the pool's credential, or look at its Pods and the ExecutorPool's conditions. `HubUnavailable` or `HubRefused` says why it cannot reach the hub |
| `executors.pools.capacity` | warn | A run has waited ten minutes while the pool has every runner `max_runners` allows, starting, idle or busy; or while the pool has room that its controller does not use. Or runs wait for a cordoned pool, which is reported at once | Raise both maxima if the cluster has room. For room left unused, check the ExecutorPool's conditions and Events: a lower `spec.maxRunners`, a quota, an admission policy or an image the nodes cannot pull. Uncordon a cordoned pool |
| `executors.pools.storage` | warn | The controller reports runner volumes stuck `Pending`, or other trouble that keeps runners from starting | `kubectl get pvc` and `kubectl describe pvc` in the controller's namespace |
| `executors.pools.protocol` | warn | A controller used in the last day speaks an older pool-controller protocol than the hub | Upgrade the controller (see [Upgrading](#upgrading)) |
| `executors.pools` | pass | The pool's runners and queue, and which build last made contact | Nothing |

### Other symptoms

**A runner Pod failed.** The controller deletes a finished runner Pod and its
Secret within a pass, so read what happened from the pool's Events. A runner
writes a one-line JSON report of how it ended to its termination log, and the
`RunnerFailed` Event quotes it:

```bash
kubectl -n cloop-gpu get events --field-selector involvedObject.kind=ExecutorPool,reason=RunnerFailed
kubectl -n cloop-gpu logs -f -l app.kubernetes.io/name=cloop-runner -c runner   # while runners are up
```

A runner whose token expired before it reached the hub, or whose token was
already redeemed, is refused at enrollment and exits with a failure. The hub
logs the refusal as `remote: connect rejected` with the reason.

**A run fails as soon as a runner takes it.** A project with no Claude or
Copilot credential granted fails with `harness_credential_missing` when the
hub hands its run to a runner. Grant one and start the run again.

**Split, Revise or the plan assistant fail on a pool-bound project.** These
dashboard calls need an executor to run on immediately, and a pool's runners
take only queued runs, so the hub answers `409 waiting_for_pool_capacity`.
Bind the project to an executor while you use them.

**Metrics.** `cloop_executor_pool_demand`, `cloop_executor_pool_runners` and
the mint and retirement counters are described under
[Executor pools in the metrics reference](../operations/metrics.md#executor-pools),
with alerts for runs that wait with no runner coming and for a controller that
keeps asking past its limit. Every change to a pool, its credentials and its
runners is in the audit trail under
[`executor_pool.*`](../reference/audit-events.md#executor_pool).

## Removing a pool

```bash
cloop executor pool revoke gpu
helm uninstall gpu -n cloop-gpu
```

Revoking the pool on the hub revokes its controller credentials, its unredeemed
runner tokens and its runners' credentials, revokes the leases their runs
hold, and cancels the runs waiting for it. A run in progress on one of its
runners is stopped.

Uninstalling the release removes the controller and, if the chart created it,
the ExecutorPool. Delete an ExecutorPool you wrote yourself with
`kubectl delete xpool <name>`. With the ExecutorPool go its runner Pods and
their Secrets. Its volumes follow `reclaimPolicy`: under `Delete` they go too,
under `Retain` they stay with the data of the projects they held. Helm leaves the
CustomResourceDefinition in place; delete it with
`kubectl delete crd executorpools.cloop.dev` once no namespace uses it.

The hub cannot delete anything in the cluster. Until someone with access to
the namespace deletes them, retained volumes keep the projects' checkouts, git
objects and caches:

```bash
kubectl -n cloop-gpu delete pvc -l cloop.dev/executor-pool=gpu
```

## How this is tested

`tests/kubecontroller` installs the controller with this chart on a real
cluster, against a real hub, and runs a pool through ten phases: scaling from
zero and back to `minRunners`, a project finding its volume again, two other
projects finding nothing of it, a reused and an expired runner token refused,
a runner killed twice under one task, the controller's leader killed mid-run,
the controller's credential revoked, and every volume scanned for credentials
afterwards (`TestExecutorPoolOnARealCluster`). CI runs it on kind in the
`kube-controller` job. The [tests/kubecontroller README](../../tests/kubecontroller/README.md)
says how to run it yourself.
