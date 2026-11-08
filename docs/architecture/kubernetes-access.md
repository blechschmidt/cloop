# Kubernetes access monitor

How cloop lets a sandbox read one namespace of a Kubernetes cluster and nothing
else, without giving it a credential that could reach the rest of the cluster.

`pkg/kubeguard` is a proxy for the Kubernetes API that runs outside the sandbox.
The sandbox's `KUBECONFIG` points at it, and the sandbox authenticates with a
short-lived bearer token. The monitor holds the real cluster credential. It
parses each request into the fields an access decision depends on (verb, API
group, resource, subresource, namespace and name), checks them against the
grant, and only then sends the request on with the credential. A namespace
allowlist is then enforced on the network path, where `kubectl` cannot ignore
it, and a grant can be read-only, which a kubeconfig has no field for.

The monitor runs inside the hub process and is off by default. Without it, a
kubeconfig grant that names namespaces or fewer than all verbs (read-only, the
default, included) is not delivered, because nothing would enforce those limits
(see [the hole it closes](#the-hole-it-closes)). An administrator can deliver
such a grant anyway, and that decision is recorded
([without the monitor](#without-the-monitor-refused-unless-acknowledged)).
Setting `executors.kube_guard.enabled: true` turns the monitor on. From then on,
every kubeconfig grant the hub delivers becomes a monitor session. See
[turning it on](#turning-it-on).

The [git interception proxy](../git-interception-proxy.md) does the same for
git, and the two packages are built the same way.

- [The hole it closes](#the-hole-it-closes)
- [Without the monitor: refused, unless acknowledged](#without-the-monitor-refused-unless-acknowledged)
- [The inversion](#the-inversion)
- [What a request is, and how it is decided](#what-a-request-is-and-how-it-is-decided)
- [The policy](#the-policy)
- [Creating a read-only grant, end to end](#creating-a-read-only-grant-end-to-end)
- [Turning it on](#turning-it-on)
- [Kubernetes shares: a cluster behind a credential plugin](#kubernetes-shares-a-cluster-behind-a-credential-plugin)
- [What it enforces, and what it does not](#what-it-enforces-and-what-it-does-not)
- [Audit events and metrics](#audit-events-and-metrics)
- [Troubleshooting](#troubleshooting)

---

## The hole it closes

Without the monitor, the only way to deliver a kubeconfig grant is to rewrite
the document. `MinimizeKubeconfig` drops every context outside `--contexts`,
pins each remaining context to an allowed namespace, and removes the clusters
and users that nothing references any more, credentials included. See
[the secrets guide](../guides/secrets.md#kubeconfig).

That is enough to limit which clusters a project can reach, because a sandbox
cannot reach a cluster it has no credential for. It cannot enforce the other two
things the grant appears to promise.

### The namespace is a client-side default

The `namespace:` field of a kubeconfig context is the value `kubectl` uses when
you do not pass `-n`. It is not a limit. A workload granted `--namespaces
team-a` receives a document that says `namespace: team-a`, and then:

```console
$ kubectl get pods                       # team-a, as configured
$ kubectl -n kube-system get secrets     # also works
$ kubectl get pods --all-namespaces      # also works
```

There is nothing unusual about the second and third commands. `-n` is the flag
every Kubernetes user reaches for first. Without the monitor, "this project may
only touch namespace `team-a`" is enforced by nothing, and you would only find
out it had been ignored from the effects.

### Read-only cannot be written down at all

A kubeconfig has no field for it. A kubeconfig carries a *credential*, and what
that credential may do is decided by the cluster's RBAC, which the hub does not
administer and usually cannot narrow.

This matters because of where these documents come from. A kubeconfig in a
cloop secret store is usually one a developer already had: the file their
cluster administrator issued them. It is often bound to a `ClusterRole` with
much more in it than `get pods`, and sometimes to `cluster-admin`. Granting it
to a project with `--namespaces team-a` would put all of that authority into a
sandbox, with only a default namespace suggesting it use less.

Closing both gaps needs a process outside the sandbox that reads each request
and decides on it, since code in the sandbox can ignore any check made inside
it. So the hub keeps the credential, the sandbox gets a token that allows only
what the policy allows, and every request passes through a process the sandbox
does not control.

---

## Without the monitor: refused, unless acknowledged

Earlier builds delivered the minimised kubeconfig whatever the grant said, so a
grant reading "read-only, namespace `app`" gave the workload everything the
kubeconfig's identity may do, with no warning anywhere. A hub without the
monitor now refuses such a grant (`ErrKubeConstraintsUnenforced`,
`pkg/secretbroker/material.go`), the same way it refuses a GitHub branch
allowlist without the git proxy:

```console
secretbroker: kubeconfig grant constraints cannot be enforced without the Kubernetes access
monitor: grant grant_1a2b… limits kubeconfig dev-kube to namespaces app and read-only access
(get, list, watch), which only cloop's Kubernetes access monitor enforces, and this hub runs
none … It is not delivered — enable executors.kube_guard (enabled: true, tls: auto), or have an
administrator acknowledge delivering it unenforced with `cloop hub grant unguarded grant_1a2b…
--reason <why>`
```

`Constraints.KubeMonitorOnly` decides which grants this applies to: those with a
namespace list that confines (anything other than `*`), or with a verb list
shorter than all eight. The empty verb list means read-only, so it claims the
most. A grant that names only contexts and allows every verb claims nothing the
monitor enforces (minimisation enforces contexts), so it is delivered as before.
The refusal reaches the project like any other refused credential: it is named
on the lease (`Lease.Refused`) and recorded in each run's journal.

The rule covers delivery into a workload. The `kubernetes` executor's own
cluster credential (the grant `--to executor:<id>` it creates Pods with) is
leased by the executor's own broker and used inside the hub process,
[never through the monitor](#what-it-enforces-and-what-it-does-not), so that
lease is marked `Requester.KubeInProcess` and is not refused. So is workspace
provisioning, which reads only GitHub tokens from the same subjects' lease. A
*run* on that executor matches the same grant, and its lease is refused like any
other.

The fix is to turn the monitor on. The alternative is an administrator's
acknowledgement, recorded on the grant with who made it, when and why:

```bash
cloop hub grant unguarded grant_1a2b3c --reason "throwaway lab cluster, no monitor yet"
cloop hub grant unguarded grant_1a2b3c --withdraw
```

or use the **Acknowledge unguarded** button on the grant's row in the Secrets
panel (`POST`/`DELETE /api/grants/{id}/unguarded`, permission `user.manage`). A
reason is required. Recording or withdrawing one writes an audit row
([`secret.unguarded_ack`](../reference/audit-events.md#secret) or
`secret.unguarded_withdraw`), and every lease that delivers such a grant says
"unguarded: … not enforced, acknowledged by …" in its summary. The Secrets panel
badges the row (`kube_delivery`: `refused`, `acknowledged`, `monitor`,
`monitor_down`, `unconstrained` or `monitor_required`). `cloop hub grant list`
shows acknowledged grants below the request queue; with `--grants` it shows
every grant and what it amounts to without the monitor. `cloop hub doctor` fails
while such a grant is unacknowledged on a hub with the monitor off, and warns
while an acknowledged one exists.

An acknowledgement does not change two things. A hub configured for the monitor
(`executors.kube_guard.enabled`) that is not running it refuses every kubeconfig
(`ErrGuardUnavailable`). And a [share the hub renews](#renewal-through-the-monitor)
is only ever delivered through the monitor, because its ServiceAccount can mint
its own tokens.

---

## The inversion

```
sandbox ──session token──▶ kubeguard ──cluster credential──▶ API server
                              │
                     Policy.Decide per request
```

The monitor works like a reverse proxy, with these differences
(`pkg/kubeguard/proxy.go`):

- **The destination never comes from the request.** It comes from the session,
  which came from a kubeconfig the hub holds. No header, path or `Host` can point
  the monitor at another cluster.
- **The credential is attached in one place**, after the decision. The header is
  `Set` rather than added, so nothing the sandbox sent survives in the credential
  slot. If the kubeconfig holds no credential at all, the request leaves with no
  `Authorization` header, rather than with whatever the sandbox supplied.
- **Impersonation headers are removed.** Kubernetes lets a credential with
  enough privilege act as another user, and a developer's own kubeconfig often
  has that privilege. Forwarding `Impersonate-User` would give the sandbox every
  identity in the cluster.
- **Hop-by-hop headers are dropped** in both directions, as RFC 7230 specifies,
  so `Connection` cannot be used to slip a header past the upstream.
- **A protocol upgrade is refused before it reaches the transport**, so the
  monitor never carries a stream it cannot read.

A refusal is returned as a Kubernetes `Status` object rather than a bare 403.
`kubectl` parses it and prints the message, so a developer sees:

```console
$ kubectl delete pod web-0
Error from server (Forbidden): this session has read-only access to the cluster,
so it may not delete pods (allowed: get, list, watch)
```

### What the sandbox holds

One file in the lease directory, with mode `0600`, which `KUBECONFIG` points at:

```yaml
apiVersion: v1
kind: Config
current-context: cloop
clusters:
  - name: cloop
    cluster:
      server: https://hub.internal:8444          # the monitor, not the cluster
      certificate-authority-data: <the monitor's CA, base64>
contexts:
  - name: cloop
    context:
      cluster: cloop
      user: cloop
      namespace: team-a                          # convenience only
users:
  - name: cloop
    user:
      token: <session-id>.<32 random bytes>
```

The file contains no bearer token for the cluster, no client certificate or key,
no CA for the cluster, and not even the cluster's address. A sandbox holding it
can reach the API server only through the monitor, because it does not know
where the API server is.

The `namespace:` line is still a client-side default that `kubectl` can
override, but that no longer matters: the monitor enforces the allowlist on
every request, whatever the context says. The line is set to a namespace the
policy permits (the minimised context's namespace if it is allowed, otherwise
the first entry in the allowlist that is not a glob), so that `kubectl get pods`
works without `-n`.

The workload also sees these environment variables, none of which is a
credential:

```
KUBECONFIG=<lease dir>/kubeconfig
CLOOP_K8S_NAMESPACE=team-a
CLOOP_K8S_ALLOWED_NAMESPACES=team-a
CLOOP_K8S_VERBS=get,list,watch
CLOOP_KUBEGUARD_SESSION=<session id>
```

`CLOOP_K8S_VERBS` lets a harness skip a write that would be refused. It
enforces nothing. `CLOOP_KUBEGUARD_SESSION` is how releasing the lease finds the
session to revoke it. The session id is not secret: it is the first half of the
token, and it appears on every audit row.

### Several grants, one document

A lease can carry more than one kubeconfig grant: two clusters, one cluster
granted twice with different namespaces or verbs, or an edited assignment whose
predecessor is not revoked yet. Every document the monitor issues names its
cluster, user and context `cloop`, and every grant renders its file as
`kubeconfig`, so older hubs wrote two files to one path: containers, devices and
Pods refused the lease (`secret_files[N] repeats path …/kubeconfig`), and on the
hub one document overwrote the other. The broker now merges them
(`pkg/secretbroker/kubemulti.go`) into one document with a context per grant:

```yaml
current-context: prod-kube                 # the narrowest grant's
clusters:
  - name: prod-kube                        # each grant's monitor endpoint …
    cluster: { server: https://hub.internal:8444, certificate-authority-data: … }
  - name: prod-kube-2                      # … the same cluster granted twice
    cluster: { server: https://hub.internal:8444, certificate-authority-data: … }
contexts:
  - name: prod-kube
    context: { cluster: prod-kube, user: prod-kube, namespace: team-a }
  - name: prod-kube-2
    context: { cluster: prod-kube-2, user: prod-kube-2, namespace: team-b }
users:
  - name: prod-kube
    user: { token: <session-id>.<…> }      # each grant's own session
  - name: prod-kube-2
    user: { token: <session-id>.<…> }
```

It is one document rather than a `:`-separated list in `KUBECONFIG`, because
`KUBECONFIG` has to stay a single path. kubectl and client-go merge a list, but
a program that passes `$KUBECONFIG` to `clientcmd.BuildConfigFromFlags`, a
script that opens it, an agent that `cat`s it and the hub doctor's own smoke
workload (`[ -f "$KUBECONFIG" ]`) all treat it as one file name. An edge agent
relocates a lease's files by rewriting each variable's leading directory, which
on every agent already deployed would move only a list's first entry, and
kubectl skips a missing file without an error. One document also sets
`current-context`, instead of leaving it to kubectl's first-file-wins rule.

- **Names** come from each grant's secret, sanitised to lower-case letters,
  digits and `-`, with `-2`, `-3` added on a collision. Each reference is renamed
  within its own document, so a context that named a user its document did not
  define still names nothing after the merge, never another grant's user with
  the same name.
- **`current-context`** is the narrowest grant's. Grants that name every
  namespace come first, then grants with a pattern, then cluster-wide ones;
  within those, read-only comes before read-write and fewer namespaces before
  more, then the order is by secret name and grant id. The order is total, so
  the same grants always render the same document, whatever order the materials
  arrive in, at dispatch or in the process that adopts the run.
- **Monitored and unmonitored grants can be mixed.** A grant the monitor holds
  becomes an entry pointing at the monitor with its session token. One the
  monitor declined contributes its minimised document's clusters, users and
  contexts.
- **The environment.** One grant renders only the variables above. With
  several, those describe the grant behind `current-context`, and three more
  describe all of them: `CLOOP_K8S_CONTEXTS` (every context, current first),
  `CLOOP_K8S_GRANTS` (a JSON array of each grant's contexts, secret, namespaces
  and verbs, and whether and under which session the monitor holds it) and
  `CLOOP_KUBEGUARD_SESSIONS`. They belong to the lease, not to one grant, so
  withdrawing a grant does not remove a description the others still need.
- **[Withdrawing one grant](../guides/secrets.md#revoking-a-grant)** removes
  only that grant's access when the monitor holds it: its entry is a session
  token, so closing the session is enough, and the document stays. An
  unmonitored grant's entry is the cluster credential itself, and no delivery
  path can cut one entry out of a file a workload may have open, so the document
  belongs to every unmonitored grant in it and goes when any of them is
  withdrawn. When every grant is monitored, the document belongs to the
  narrowest, and withdrawing that grant removes it too: some grant's binding has
  to name the file, or no delivery path would know the workload needs one. Both
  cases err toward less access.
- **A restart.** The monitor receives each grant's minimised document under the
  grant's own names, before the merge renames anything, and records the
  session's context under that name. The process that adopts the run re-derives
  the same document from the grant ([below](#a-hub-restarted-mid-run)), so each
  session is restored under the token the merged document already holds.

### What the hub holds

The hub keeps one `kubeguard.Session` per delivery, in memory. It holds the
parsed cluster credential (unexported and never serialised: `Session` has no
`MarshalJSON`, and every exported field on it is safe to expose), the policy,
the attribution labels, and a SHA-256 of the bearer token. After minting, the
token itself exists in one place only: the kubeconfig delivered into the
sandbox. A dump of the hub's memory or a leaked session struct yields no token
that can authenticate.

Authentication compares the hash of the full token in constant time. An unknown
session id is hashed anyway before it is rejected, so timing does not reveal
whether the session does not exist or the token is wrong. Both cases return the
same error for the same reason: telling them apart would let someone enumerate
live sessions.

The kubeconfig is parsed by `pkg/executor/kubernetes.ParseKubeconfig`, the
driver's own parser, so the three refusals that protect a tenant-supplied
kubeconfig apply here too and stay in step with the driver: an `exec` credential
plugin, an `auth-provider` block, and a credential that points at a file path on
the control-plane host. A cluster whose kubeconfig signs people in through a
plugin (AKS, EKS, GKE) is shared through a ServiceAccount instead, created from
the developer's own terminal. See
[Kubernetes shares](#kubernetes-shares-a-cluster-behind-a-credential-plugin).

**What it writes down.** Each session is also recorded in `proxy_sessions`: its
id, the token's SHA-256, the cluster URL, the context, the policy, the lease and
grant it depends on, the run, and which hub process serves it. If this process
stops, the process that adopts the run uses the record to restore the session.
The record never holds the token or the cluster credential; a restored session
re-derives the kubeconfig from the lease's grant. See
[a hub restarted mid-run](#a-hub-restarted-mid-run).

### What a leaked session token is worth

| Leaked | Worth |
| --- | --- |
| **Session token** | What the policy allows, for the rest of the TTL, against one cluster, through one monitor. Under the default that is get, list and watch in the granted namespaces: no exec, no port-forward, no writes, and nothing once the TTL lapses or the lease is released. Useless against the API server directly, which has never seen it. |
| **Kubeconfig delivered into the sandbox** (what a hub without the monitor still does for a grant that claims every verb in every namespace, or one an administrator [acknowledged](#without-the-monitor-refused-unless-acknowledged)) | Whatever the cluster's RBAC grants the user who uploaded it, which for a personal kubeconfig is often cluster-admin: every namespace, every verb, `exec` into any pod, from anywhere on the network, until somebody rotates the credential, which means rotating it for its owner too. |

Two more differences:

- **Detection.** With a session token, each refused attempt leaves a
  `kubeguard.request_denied` row. With a kubeconfig, there is only what the
  cluster's own audit policy records about successful requests, attributed to
  the developer whose credential it was.
- **Revocation.** Releasing the lease cuts the session off at its next request,
  with no call to the cluster and no coordination. Revoking a delivered
  kubeconfig means rotating a credential in the cluster and issuing the new one
  to its owner.

---

## What a request is, and how it is decided

### The tuple

`pkg/kubeguard/apirequest.go` turns an HTTP method, path and query into an
`APIRequest`: verb, API group, API version, resource, subresource, namespace and
name, plus whether it is a resource request at all and whether the client asked
to switch protocols. It is a pure function with no I/O. Every policy decision is
made about this struct, so the package's security depends on this parse.

The parse follows the API server's own `RequestInfoFactory`. If the monitor and
the cluster disagree about which namespace a request is about, even for one path
shape, that disagreement is a bypass: a request the monitor reads as namespace
`team-a` and the cluster reads as `kube-system` passes an allowlist that seems to
work. So:

- Repeated slashes collapse, and `.` and `..` segments are resolved before
  anything is matched, so `/api/v1/namespaces/team-a/../kube-system/secrets`
  does not parse as `team-a`. `net/url` has already percent-decoded the path by
  then, so `%2e%2e` arrives as `..` and is resolved like any other.
- `/api/v1/namespaces/team-a` is a request about the namespace *object*, and its
  namespace is also `team-a`. Both readings are recorded; they do not conflict.
- A path that is not recognised as a resource request becomes a
  **non-resource** request rather than an error. The policy checks it against the
  non-resource allowlist and denies it by default.

### Method to verb

| HTTP | Names an object | Verb |
| --- | --- | --- |
| `POST` | either | `create` |
| `PUT` | either | `update` |
| `PATCH` | either | `patch` |
| `DELETE` | yes | `delete` |
| `DELETE` | no | `deletecollection` |
| `GET` / `HEAD` | yes | `get` |
| `GET` / `HEAD` | no | `list` |
| `GET` / `HEAD` with `watch=true` | either | `watch` |
| anything else | either | the lowercased method, so the denial can name it |

Two of these rows matter most. `DELETE` without a name is `deletecollection`:
if it were `delete`, an allowlist that permits removing one object would also
permit emptying a namespace. And `watch` is a verb of its own, as it is in RBAC,
so a policy can allow `get` and `list` but not `watch`, and the monitor enforces
it.

Non-resource URLs use RBAC's other spelling (`get`, `post`), because that is how
`nonResourceURLs` rules are written.

### The order of the checks

`Policy.Decide` runs seven checks, ordered so that the operator is told the most
specific and most alarming reason:

1. **A dangerous subresource**, or the TokenRequest API, whatever the verb.
2. **A write to RBAC or to a CertificateSigningRequest**, under every grant.
3. **A protocol upgrade.**
4. **A non-resource URL**: reads only, and only if it is in the allowlist.
5. **The verb.**
6. **The resource.**
7. **The namespace.**

A write that passes all seven and could
[mint a credential by what it contains](#writes-that-would-mint-a-credential) is
then read and decided by its body.

### Subresources that are not data

Five subresources are refused for every verb, and no policy can allow them:

| Subresource | What it gives the caller |
| --- | --- |
| `exec` | a shell inside the pod |
| `attach` | a shell on a process already running in it |
| `portforward` | a tunnel to anything the pod can reach, which on a cluster network is usually everything |
| `proxy` | arbitrary requests to the kubelet or a Service, made with the API server's credential |
| `ephemeralcontainers` | a new container inside a running Pod, as whichever ServiceAccount that Pod runs as, with its token mounted; the `edit` role includes it |

This is the most important rule in the package, because checking the verb alone
gets it wrong:

```
GET /api/v1/namespaces/team-a/pods/web-0/exec?command=sh
```

A verb allowlist of `{get, list, watch}` admits that request. The method is
`GET` and the request names an object, so the verb is `get`. The API server
answers by upgrading the connection and giving the caller a shell. "Read-only"
would have meant remote code execution on the cluster.

A sandbox that needs to exec into pods needs a grant that does not go through
the monitor.

One more is refused on the same terms, for a different reason:
`serviceaccounts/token`, the TokenRequest API. It does not open a session. It
returns a token for the cluster itself, which would never pass through the
monitor again and would last as long as the caller asked. A write grant's
`create` admits it as readily as a ConfigMap, so it is refused for every verb
under every grant. [Self-renewing shares](#renewal-through-the-monitor) need
this too: their ServiceAccount may create its own token, which is how the hub
renews them, and only the hub may use that permission.

```console
$ kubectl -n cloop-shares create token cloop-aks-dev-3f9c2a1b
error: failed to create token: serviceaccounts/token is refused by the cloop Kubernetes monitor
for every verb, under every grant: it answers with a token for the cluster itself, which would
never pass through this monitor again. …
```

### Writes that would mint a credential

The verb check cannot tell a ConfigMap from a credential, and a write grant
holds `create` on both. A workload that may write to a namespace (the `edit`
role may create Secrets, Pods and Deployments) could otherwise give itself a
ServiceAccount credential that never passes through the monitor, is not bounded
by any grant's TTL, and is not reached by a revocation. The monitor refuses
these writes:

| What the workload writes | Why it is a credential | Refusal |
| --- | --- | --- |
| a Secret of type `kubernetes.io/service-account-token`, or a write touching the `kubernetes.io/service-account.name`/`.uid` annotations | the token controller fills it in with a non-expiring token for the named ServiceAccount | `service_account_token_secret` |
| a Pod, PodTemplate, ReplicationController, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job or CronJob naming a `serviceAccountName` (or the deprecated `serviceAccount`) other than `default` | the cluster mounts that ServiceAccount's token into the container, which can print it to its log | `workload_service_account` |
| any custom resource naming such a `serviceAccountName` (any API group the API server does not serve itself, including groups under `k8s.io`: the Gateway API's resources are CRDs too) | Tekton TaskRuns, Argo Workflows and Flux Kustomizations act as the ServiceAccount they name | `workload_service_account` |
| a workload asking for `hostPID`, `hostIPC`, `hostNetwork`, a privileged container or a `hostPath` volume | the node holds every Pod's token and the kubelet's own credential | `host_access` |
| a patch to a workload that already runs as another ServiceAccount, or already reaches the node | a patch keeps every field it does not mention, so a new image for the deployer's Deployment runs the attacker's code as the deployer | `workload_service_account` / `host_access` |
| any write to a RoleBinding or ClusterRoleBinding | it can bind a subject to more, such as the namespace's default ServiceAccount, which any Pod runs as | `rbac_binding` |
| any write to a Role or ClusterRole | changes what every subject already bound to it may do | `rbac_role` |
| any write to a CertificateSigningRequest, its approval or status | a signed client certificate is a credential for the cluster | `certificate_signing_request` |

A Pod that runs as the namespace's `default` ServiceAccount passes, as does
everything not in this table.

**How the body is read** (`pkg/kubeguard/inspect.go`). Only writes to the
resources above are read: `create`, `update` and `patch` of the resource itself.
A subresource's body (a Scale, a Status) cannot change who a workload runs as.
The body is read whole, up to the session's body cap, checked, and then
forwarded unchanged. JSON is walked token by token, so every occurrence of a
repeated key is checked, not only the one a decoder would keep. YAML
(`application/yaml`, server-side apply) is decoded with a parser that refuses
repeated keys and limits aliasing and depth, and that treats a YAML 1.2 `yes` as
the YAML 1.1 `true` the API server's decoder reads. A JSON patch is checked
operation by operation, by path and value, and a `copy` or `move` on a workload
is refused, because what it writes comes from elsewhere in the object. A patch
to a workload is also checked against the object it patches: the monitor first
reads the object with the session's credential, and refuses a patch to one that
already runs as another ServiceAccount. A body the monitor cannot read
(protobuf, CBOR, a compressed body, malformed JSON) is refused with
`unreadable_body`. kubectl, Helm and client-go send JSON by default.

```console
$ kubectl -n team-a create -f pod-as-deployer.json
Error from server (Forbidden): error when creating "pod-as-deployer.json": create pods is refused
by the cloop Kubernetes monitor: it names ServiceAccount "deployer" (serviceAccountName), whose
token the cluster would hand the workload — a credential outside this monitor, which no
revocation reaches. Workloads created through it run as the namespace's default ServiceAccount
```

Each refusal has its own `reason` on the
[`kubeguard.request_denied`](../reference/audit-events.md#kubeguard) row and its
own label on `cloop_kubeguard_denials_total`. The cost is that a Helm chart that
creates its own ServiceAccount, Role and RoleBinding, or a Deployment that runs
as a named ServiceAccount, cannot be installed through the monitor. Install
those as a cluster administrator, and run the workload's own work through the
grant.

### Protocol upgrades

Every upgrade the Kubernetes API offers a client is a streaming session: SPDY
for exec, attach and port-forward, and websockets for those and for watch. The
subresource rule already refuses the first three. That leaves watching over a
websocket, the only upgrade a read-only session could legitimately want, and
`kubectl` does not use it: client-go watches over chunked HTTP/1.1 and HTTP/2,
which the monitor forwards unchanged and flushes as it goes.

So refusing every upgrade costs nothing that normal use needs, and the boundary
does not depend on correctly tracking a hijacked bidirectional stream that the
monitor cannot parse.

`kubectl get pods -w` works. `kubectl exec`, `kubectl attach`,
`kubectl port-forward` and `kubectl proxy` do not, by design.

---

## The policy

A session's policy has five fields (`pkg/kubeguard/policy.go`): four allowlists
and a ceiling. What an empty list means differs from field to field:

| Field | Empty means | Matching |
| --- | --- | --- |
| `verbs` | **read-only** (`get`, `list`, `watch`) | exact, from RBAC's eight |
| `namespaces` | no namespace confinement | glob (`path.Match`, `*` admits all) |
| `resources` | every resource | glob against `resource` (core group) or `group/resource` |
| `non_resource_paths` | the discovery set below | glob, plus a trailing `/**` for any depth |
| `max_body_bytes` | 3 MiB | a size, not a pattern |

Each list holds at most 256 patterns, each at most 256 characters long. A
pattern containing `..`, or one that `path.Match` cannot parse, is refused
rather than stored.

**An empty verb list means read-only.** A grant that names a cluster and says
nothing about verbs gets read access, not the credential's full authority. This
is the only place in the constraint model where an empty list means neither
"allow all" nor a validation error. When a grant says nothing about verbs, the
safe assumption is that nobody asked to change anything.

**Resource patterns match without the subresource**, so `pods` admits
`pods/log`. Subresources are governed by the verb and by the
dangerous-subresource rule, not by this list.

**The default non-resource set is the discovery endpoints:**

```
/  /api  /api/*  /apis  /apis/*  /apis/*/*  /version  /openapi/**
/healthz  /readyz  /livez
```

`kubectl` cannot work without them. `kubectl get
pods` begins by fetching `/api` and `/apis` to learn which groups exist, then
`/api/v1` to learn that pods are namespaced. If discovery is denied, every
command fails with "the server could not find the requested resource", which
looks like a cluster problem rather than a policy one. None of these paths
returns cluster data: they return group names, type schemas, a build version
and "ok".

### Namespace confinement is two refusals, not one

When a namespace allowlist exists, the monitor refuses:

- a request naming a namespace outside it, such as
  `kubectl -n kube-system get secrets`;
- a request naming no namespace at all. `kubectl get pods -A` and
  `GET /api/v1/secrets` are collection reads across the whole cluster. If they
  were allowed because they name no namespace, the allowlist would let through
  the one request that asks for everything at once.

The second rule also refuses cluster-scoped resources: `nodes`,
`persistentvolumes`, `storageclasses` and `namespaces` itself. A grant confined
to namespaces has not been given the cluster. To allow those resources, add them
to `resources` and drop the namespace list, or issue a second, cluster-scoped
grant.

### The deployment floor and the grant intersect

`executors.kube_guard.verbs`, `.namespaces` and `.resources` set a **hub-wide
floor**. Each grant carries its own policy, and the session gets
`floor.Intersect(grant)`:

- If you set the floor to read-only, every grant on the hub is read-only,
  whatever it asks for.
- A grant that asks for less than the floor allows gets only what it asked for.
- If you leave the floor empty, each grant decides for itself, and a grant that
  says nothing still gets read-only, because that is also the default for a
  grant.

Verbs are a plain set intersection, since there are only eight of them. The glob
lists cannot be intersected that way, because there is no general way to compute
the intersection of two glob languages. Instead, the narrowing is conservative:
an entry from the grant survives only if the floor admits it as a literal
string. A floor of `team-*` over a grant for `team-a`
narrows correctly, because the floor's pattern matches the grant's string. A
floor of `app-1` over a grant for `app-*` keeps nothing, even though `app-1` is
in both.

**Every dimension fails closed.** An empty intersection on any of them refuses
the lease instead of producing a session, and the error names both sides:

```
grant grant_187bd2… cannot be honoured under this hub's kube_guard policy
(read-only ns=team-a): policy permits no verbs

grant grant_9c41af… cannot be honoured under this hub's kube_guard policy
(read-only ns=team-a): namespaces: the grant asks for team-b but this hub's
policy floor allows only team-a, and no entry of the first is covered by the
second; widen the floor or narrow the grant to a literal subset of it
```

The glob dimensions have to refuse rather than return an empty list, because an
empty `Namespaces` list means "no namespace confinement", not "no namespaces".
Returning one would turn two policies that both forbid reading `kube-system`
into a session that can read every namespace in the cluster. So `Intersect`
returns an error, and `GuardKubeconfig` turns it into a failed lease.

In practice this rarely happens: the usual floor is empty or `*`, and then
nothing is narrowed at all. If you do set a floor, write it as a literal
superset of every grant. A floor whose patterns match every namespace string any
grant names narrows correctly, and a mismatch is refused with an error at lease
time instead of leaving a gap.

---

## Creating a read-only grant, end to end

The grant workflow is the same with the monitor on. These two commands produce a
delivery the monitor enforces:

```console
$ cloop secret mint prod-kube --kind kubeconfig --file ~/.kube/config
✓ minted prod-kube (kubeconfig) as sec_382c3ca8e0866696a8c60727
  no grant yet — nothing can use it until you run 'cloop secret grant'

$ cloop secret grant prod-kube \
    --to project:/srv/app \
    --contexts prod \
    --namespaces team-a \
    --ttl 12h
✓ granted prod-kube to project:/srv/app
  grant:       grant_187bd292e8f8da691fa698ea
  constraints: ns=team-a ctx=prod
  expires:     2026-08-22T21:51:12Z (in 12h0m0s)
```

That grant is read-only: `--verbs` was not given, and an unset verb list means
`get`, `list`, `watch`. The summary does not mention verbs, because it prints
the constraints as written and the verb list is empty.

To make read-only explicit, or to ask for more:

```console
# explicit read-only — identical behaviour, visible in the grant summary
$ cloop secret grant prod-kube --to project:/srv/app --contexts prod \
    --namespaces team-a --verbs get,list,watch --ttl 12h

# a project that deploys: reads, plus the writes a rollout needs
$ cloop secret grant prod-kube --to project:/srv/app --contexts prod \
    --namespaces team-a --verbs get,list,watch,create,update,patch --ttl 2h
```

The verbs are RBAC's, spelled as RBAC spells them, so you can copy a list from
an existing `Role`: `get`, `list`, `watch`, `create`, `update`, `patch`,
`delete`, `deletecollection`. A misspelling is refused when the grant is
created, instead of failing later in somebody's run.

A kubeconfig grant still needs `--namespaces`, `--contexts` or both. There is no
implicit wildcard, and `--verbs` does not replace them: the namespace list says
which parts of the cluster, and the verb list says what may be done to them.

To check what will be delivered without materialising anything:

```console
$ cloop secret lease --project /srv/app --executor k8s-prod
1 material(s), lease expires 2026-08-22T09:51:12Z

  prod-kube (kubeconfig)
    grant:       grant_187bd292e8f8da691fa698ea
    constraints: ns=team-a ctx=prod
    delivers:    kubeconfig read-only ns=team-a via monitor, contexts: prod/team-a
    env:         CLOOP_K8S_ALLOWED_NAMESPACES, CLOOP_K8S_NAMESPACE, CLOOP_K8S_VERBS, CLOOP_KUBEGUARD_SESSION
    files:       kubeconfig
```

Look for `via monitor`. Without the monitor, this grant is refused, because
its namespace and verb limits are ones only the monitor can enforce (see
[Without the monitor](#without-the-monitor-refused-unless-acknowledged)). If an
administrator has acknowledged it, the lease delivers the cluster credential
itself, with the same constraints and TTL but nothing enforcing them, and reads
`kubeconfig read-only contexts: prod/team-a` followed by an `unguarded:` note
naming who acknowledged it. The context summary comes from the minimised
document rather than the delivered one, because under the monitor the delivered
kubeconfig names one synthetic context called `cloop`, which says nothing about
the access.

---

## Turning it on

Add one section to the hub's `.cloop/config.yaml`:

```yaml
executors:
  kube_guard:
    enabled: true
    tls: auto                                    # the hub issues the certificate
    listen_addr: "0.0.0.0:8444"                  # where the monitor binds
    advertise_url: "https://hub.internal:8444"   # what the SANDBOX connects to
    # or, instead of tls: auto, an operator's pair:
    # cert_file: /etc/cloop/tls/kube-guard.crt
    # key_file: /etc/cloop/tls/kube-guard.key
    # ca_file: /etc/cloop/tls/kube-guard-ca.pem  # empty falls back to cert_file
    min_tls_version: "1.2"                       # or "1.3"; empty means 1.2
    session_minutes: 60                          # 0 means 60; ceiling is 720
    # A hub-wide ceiling. Empty lets each grant speak for itself.
    verbs: [get, list, watch]
    namespaces: ["team-*"]
    resources: ["pods", "services", "configmaps", "apps/deployments"]
    audit_allowed: false                         # true: audit forwarded requests too
```

`cloop hub bootstrap` writes this section with `tls: auto`, next to the git
proxy's, using the host of `--external-url`. With the Helm chart, set
`executor.kubeGuard.enabled=true` and a certificate source in
`executor.monitorTLS` (`auto`, or a Secret). The chart advertises the monitor at
the hub's Service name and adds the port to the Pod and the Service. For a
Secret, it points `ca_file` at the CA it generated or was given. See
[deploy/README.md](../../deploy/README.md#the-git-proxy-and-the-kubernetes-access-monitor).

Resource patterns name the resource, never a subresource. `pods` already admits
`pods/log`, and a pattern written as `pods/log` matches nothing, because
patterns are matched against `resource` for the core group and `group/resource`
otherwise.

- **Off by default.** The monitor changes which server a sandbox's `kubectl`
  talks to, so it stays off until an operator turns it on, including after an
  upgrade.
- **TLS is required.** The session token travels in an `Authorization` header on
  every request, and plain HTTP would expose it. An enabled section with neither
  `tls: auto` nor both `cert_file` and `key_file` is switched off at load. It is
  never treated as `tls: auto`, which has to be chosen explicitly.
- **`tls: auto` issues the certificate from the hub's own CA**, the one the
  [git proxy's](git-proxy.md) comes from: created once per control plane, sealed
  under `CLOOP_SECRET_KEY` and replaced online with
  [`cloop hub ca rotate`](../operations/runbook.md#rotating-the-hub-ca). The
  leaf lasts 72 hours, names the host of `advertise_url` (and of `listen_addr`,
  if that names a specific address), and is renewed by the cluster leader with
  two days to spare. Every kubeconfig the monitor issues carries the CA as
  `certificate-authority-data`, and both CAs during a rotation, so a kubeconfig
  minted after the new CA is staged keeps working once it is activated; the run
  it was minted for records which it carries. Needs `CLOOP_SECRET_KEY`; cannot be
  combined with `cert_file`, `key_file` or `ca_file`.
- **With an operator's certificate pair, `ca_file` makes this easier to deploy
  than the git proxy.** A kubeconfig can carry its own trust anchor, so the PEM
  is embedded in the delivered document as `certificate-authority-data`, and a
  self-signed hub certificate needs no change to the sandbox image. An empty
  `ca_file` falls back to `cert_file`, which is right for a self-signed
  certificate and harmless for a publicly signed one.
- **`advertise_url` must be reachable from where `kubectl` runs**, which is often
  not the address the hub sees itself at: a Kubernetes Service name for the Pod
  backend, `host.docker.internal` or `host.containers.internal` for a
  containerised agent, or the hub's address on the local link for an edge
  device. It becomes the `server:` field of a kubeconfig, so it must be a bare
  `https://` base URL; with a path, query or fragment, requests go to paths
  nothing serves. If it is empty, the bound address is used, which is only
  correct when the sandbox shares the hub's network namespace.
- **A session lasts `session_minutes` from dispatch, not for the whole run.** The
  default is 60 and the ceiling is 720 (twelve hours), because a session that
  outlives a working day is no better than handing the sandbox the kubeconfig
  itself. An out-of-range value is refused when it is written
  (`cloop config set`, `cloop
  config validate`) and reset to the default with a warning if it reaches `Load`
  by some other route. The monitor itself refuses a TTL above the ceiling instead
  of shortening it, so a misconfiguration shows up at once rather than as a
  `kubectl` that stops working halfway through a long run. A run that outlives
  its session fails its next API call with a message that says so.

The configuration is checked when it is written, not only when the hub starts.
`verbs`, `namespaces` and `resources` go through the same `Normalize()` and
`Validate()` the monitor enforces with, so a misspelt verb, a malformed glob or a
pattern containing `..` is refused when it is written, instead of becoming an
allowlist that denies everything. A rejected policy resets all three fields
together rather than dropping the bad entry, because a half-applied policy is
one nobody wrote, and the built-in default is narrower than any override. The
same applies to `session_minutes`, `min_tls_version`, `listen_addr` and
`advertise_url`. Where a repair could only produce an unusable or unsafe
monitor, it switches `enabled` off.

A hub that started the monitor logs one line:

```
ui: kubernetes access monitor on 0.0.0.0:8444, advertised as https://hub.internal:8444; policy floor read-only ns=team-*
```

A hub that could not start it still comes up, and logs what is not in effect:

```
ui: kubernetes access monitor NOT started: kubernetes monitor listen on 0.0.0.0:8444: bind: address already in use
    executors.kube_guard is enabled, so no kubeconfig grant can be
    delivered: leases needing one will be refused rather than handed the
    cluster credential directly. Fix the section or set enabled: false.
```

### Checking it from the outside

[`cloop hub doctor`](../operations/runbook.md#configuration-health-cloop-hub-doctor)
reports on the monitor under the `kubeguard.*` checks. Run it even when nothing
seems wrong: a hub with the monitor off leases, dispatches and runs `kubectl`
the same way as one with it on, so a misconfiguration is easy to miss.

| Check | What it catches |
| --- | --- |
| `kubeguard.enabled` | The monitor is off while Kubernetes access is configured. **Fails**, naming each grant, while an active kubeconfig grant claims namespaces or verbs and nobody has acknowledged delivering it without the monitor (such a grant is refused at every dispatch). **Warns** while acknowledged grants are delivered unenforced, naming who acknowledged each and why, and while grants that claim nothing are delivered with the cluster credential. A pass states the policy and session length in force. |
| `kubeguard.tls` | `cert_file`, `key_file` or `ca_file` is missing or unreadable, so the monitor will not start and every kubeconfig lease will be refused. Under `tls: auto`: no `CLOOP_SECRET_KEY` (the monitor will not start), or a leaf certificate that does not chain to the hub CA, has less than a day left (the leader renews with two left), or does not name the host of `advertise_url`. Passes before the hub has first started, when nothing has been issued yet. |
| `kubeguard.advertise_url` | Unset, or loopback, so `kubectl` in a Pod or on an edge device cannot connect. This is the most common misconfiguration, because the wrong value works on the machine where it was written. |
| `kubeguard.advertise_reachable` | Nothing is listening at the advertised address. Reported but never failed: the hub is not on the sandbox's network, so a Service name that does not resolve on the hub is often correct. |
| `kubeguard.verbs` | The deployment floor permits writing, so a grant on this hub may be given authority to change a cluster. |

When the monitor fails to start, the dashboard still comes up, because
`cloop ui` is also how a single-project install runs. But kubeconfig leases
stop: a hub configured to intercept never falls back to delivering the cluster
credential. Everything that is not a kubeconfig grant is unaffected.

A milder message,
`ui: kubernetes monitor decisions will go to stderr, not the audit trail: …`,
means the monitor still enforces the policy, but its decisions are not being
recorded in the database.

### Proven on a cluster

[`tests/kube`](../../tests/kube/README.md) puts the monitor in front of a real
API server on every CI run. (Before it, the monitor's tests used a fake API
server on loopback, and the device kit's stub read the kubeconfig with `sed` and
spoke `curl`.) It runs against the hub the Helm chart installs on kind, with
`executor.kubeGuard` on and `auditAllowed` set, on one replica and again on a
hub cluster of three, where the Pod's requests reach members that did not mint
its session and are forwarded:

- A kubeconfig for a ServiceAccount that may edit a test namespace is stored as
  a secret and granted to a project for that namespace with no verbs, so a
  refused write can only have been refused by the monitor.
- The task's Pod receives a kubeconfig whose `server:` is the monitor's Service
  URL and whose CA is the chart's. The real `kubectl` in it runs
  `kubectl get pods` (discovery and the list, forwarded with the cluster
  credential) and `kubectl create configmap`, refused as read-only before the
  API server sees it (`K0`–`K2`).
- The same kubeconfig is granted a second time, with `create`, for a second
  namespace the ServiceAccount may also edit. The Pod receives one kubeconfig
  with a context per grant and the read-only one as `current-context`.
  `kubectl --context` reaches each grant's namespace through the monitor and is
  refused in the other's and in `kube-system`, both of which the cluster
  credential could read. The second context's `create configmap` lands in its
  namespace (`K4`).
- The audit trail holds a `kubeguard.request_allowed` row for the list and a
  `kubeguard.request_denied` row for the create, both naming the run's project,
  and an allowed row for the second grant's write.
- The refused ConfigMap does not exist, and the cluster credential reached no
  part of the Pod.
- The project the Pod runs is not in the repository: `acme/granted` holds no
  `.cloop/`, and the goal and the task exist only on the hub, reaching the Pod
  as the project seed in its lease Secret. Afterwards the hub's plan shows the
  task done (the outcome came back as a frame at the end of the Pod's log), and a
  second Start does not run it again. See
  [the seed in a Secret, the outcome in the log](executors.md#kubernetes-the-seed-in-a-secret-the-outcome-in-the-log-task-20402).

Not covered: watches and the subresource refusals (`exec`, `attach`,
`portforward`, `proxy`), which unit tests check against the fake API server; a
delivered kubeconfig's default namespace, because the run names the namespace
with `-n`; and a Pod's direct route to the API server, which only a CNI that
enforces NetworkPolicy closes. CI's kind cluster does not, as the hub's probe
reports on every run.

### Where it runs, and why there is no `cloop kube-guard`

The monitor is a background service of the hub process, started from
`bootstrapExecutors` (`pkg/ui/kubeguard.go`) alongside the git proxy. There is no
standalone command.

Sessions live in memory, in a `kubeguard.Registry`, and they hold the cluster
credential. The process that mints a session has to be the one that serves it.
A separate `cloop kube-guard` would authenticate against an empty registry and
refuse every request the hub had authorised. Making one work would need a shared
session store holding the cluster credentials, which would keep kubeconfigs at
rest in a second place. The session record holds none of that. Its job is to
restore a session in the process that adopts its run.

So the monitor is a single instance per process and must start before any
executor registers, for the same reason as the git proxy: a broker constructed
before the monitor existed would route nothing through it.

### A hub restarted mid-run

A device keeps running its task while its hub restarts. The process that adopts
the run takes over its lease and restores the monitor sessions that lease fed,
so the workload's next `kubectl` call is served with the bearer token it already
holds.

A hub that is stopped gracefully suspends a recorded session: it stops serving
it, writes no close row, and leaves the record open. A SIGKILL leaves the same
state. When the device's agent reconnects and the run is adopted, each open
session the run's lease feeds is retired if it lapsed in the meantime.
Otherwise it is taken over by a conditional write on its holder (if two
processes adopt the run, only one gets it) and restored under its id and token
hash, with:

- **its cluster credential re-derived from the grant**: the grant's kubeconfig,
  minimised the same way as when the session was minted, and refused if it no
  longer names the cluster the session was pinned to;
- **its policy narrowed, never widened**: the deployment floor intersected with
  the grant, as a fresh mint would compute it, then intersected again with what
  the session was given;
- **its deadline held to this hub's session TTL** from when it was issued. A
  record no mint could have written (a deadline beyond the 12-hour ceiling, or
  no issue time) is refused.

A [`kubeguard.session_restored`](../reference/audit-events.md#kubeguard) row names
the process that held the session before. If the grant was revoked or expired
while no process held the lease, the lease is refused, the sessions are closed
with the reason, and the device is scrubbed. A request that arrives before the
run is adopted, presenting a session whose holder stopped, waits up to 60
seconds for the restore instead of failing (kubectl's burst of discovery
requests shares one wait), and gets a 401 if nothing restores the session. The
[git proxy page](git-proxy.md#a-hub-restarted-mid-run) explains why a session
is not restored on demand. A restore that failed for a reason that may pass is
retried on the lease's keepalive and on the next request, unless another
process has taken over the session or the lease in the meantime. The leader's
janitor retires the records of sessions that closed or lapsed.

---

## Kubernetes shares: a cluster behind a credential plugin

Managed clusters usually sign people in through an **exec credential plugin**:
`kubelogin` on AKS with Entra ID, `aws eks get-token` on EKS, or
`gke-gcloud-auth-plugin` on GKE. The hub refuses such a kubeconfig, because
running the plugin would execute a program named in an uploaded file on the
control-plane host. Without shares, a developer has to create a ServiceAccount,
choose and bind roles, mint a token and assemble a kubeconfig by hand, and the
token then expires mid-run, because managed API servers cap how long a
TokenRequest token may live.

`cloop remote kube share` does that work from the developer's own terminal, and
the hub keeps the result working:

```console
$ cloop login https://cloop.example.com
$ cloop remote kube share aks-dev --context aks-dev --namespaces payments,payments-staging
```

### What runs where

| Step | Where | With what |
| --- | --- | --- |
| Run the exec plugin | the developer's machine | `pkg/kubeexec`: client.authentication.k8s.io `v1` and `v1beta1` ExecCredential, `interactiveMode` (`Never`, `IfAvailable`, `Always`), `provideClusterInfo` with the cluster's `client.authentication.k8s.io/exec` extension, the plugin's own stderr for its device-code prompt, and its stdout read under a 1 MiB cap and never echoed into an error |
| Create the ServiceAccount and its bindings, mint the token | the cluster, as the developer | the credential the plugin printed |
| Store the share | the hub, as the developer | `POST /api/secrets` over the `cloop login` session, as a personal secret, the same way the dashboard stores one |
| Renew the token | the hub | the share's own token, through its self-renewal Role, when the hub runs this monitor |
| Revoke | the hub's authorisation, the cluster, then the hub | `GET /api/secrets/{id}/authorize`, the developer's credential again, then `DELETE /api/secrets/{id}` |

The hub never runs the plugin. Only `cmd` imports `pkg/kubeexec`, so no package
the hub, the monitor, the broker or an executor runs can reach it
(`TestOnlyTheTerminalImportsTheCredentialPluginRunner`). The kubeconfig the hub
stores is static (server, CA and one bearer token) and passes the same
`ParseKubeconfig` check as every other kubeconfig. The dashboard refuses an
exec-plugin kubeconfig at upload. The error names the plugin and gives the
`cloop remote kube share` command with the hub's URL, the chosen name and the
document's context and namespace filled in.

### What a share creates

| Object | Scope |
| --- | --- |
| ServiceAccount `cloop-<name>-<id>`, `automountServiceAccountToken: false` | in `--sa-namespace` (read access: the first shared namespace by default) |
| RoleBinding to ClusterRole `view` (`edit` with `--access write`) | in each of `--namespaces`; a ClusterRoleBinding only with `--cluster-wide`, and only for read access |
| Role `…-renew`: `create` on `serviceaccounts/token`, `resourceNames: [the ServiceAccount]`, and its RoleBinding | in the ServiceAccount's namespace, and only when the hub renews the share |

Every object carries `cloop.dev/kube-share=<id>` and
`app.kubernetes.io/managed-by=cloop`, plus annotations naming the share, the
hub, the owner and the access. The owner annotation is the hub's own key for the
person sharing (a lowercased email, or `sub:` followed by the subject), which
the terminal reads from the `identity` field of `/api/me`. The label has nothing
in common with the `kubernetes` executor's own label (`cloop.dev/managed`), so
the executor's orphan sweep never mistakes a share for something it owns.

The secret's metadata records the share (`kube.share`, `kube.namespaces`,
`kube.access`, `kube.renewal`, `kube.context`). The hub, never the client,
writes every field that a revoke or a renewal acts on, because the uploader
controls the rest of the metadata and a revoke or renewal runs with somebody
else's credentials, often an administrator's:

| Key | Written from |
| --- | --- |
| `kube.service_account` | the token's claims, which must name the share's own ServiceAccount (`cloop-<name>-<id>`, in a valid namespace), or the upload is refused |
| `kube.issued_at`, `kube.expires_at` | the token's claims |
| `kube.server`, `kube.ca_sha256` | the stored kubeconfig: its server, and the SHA-256 of the CA it trusts (`none` when it names none) |
| `kube.owner` | the authenticated uploader |
| `kube.objects` | what the share's plan creates, worked out from the fields above, never the client's list |

The hub cannot verify the token's claims at upload without asking the cluster.
That is why the claims must name the share's own ServiceAccount, and why revoke
and renew also [check the cluster's own objects](#what-revoke-and-renew-trust).

**A write share's ServiceAccount must live in a namespace it cannot write to.**
In its namespace, `edit` may create Pods and Secrets, impersonate
ServiceAccounts and create tokens for them. A ServiceAccount that can write
where it lives can therefore give a workload its own credential (a Pod running
as it whose logs print its token, or a Secret of type
`kubernetes.io/service-account-token`) through requests the monitor reads as
ordinary writes. That credential would bypass the monitor and outlive the
share's TTL. So `--access write` requires an `--sa-namespace` outside
`--namespaces`, and cluster-wide write access is refused, because there is no
namespace outside it. `view` can read neither Secrets nor the logs of a Pod it
could have started, so a read share may live where it reads.

### Renewal through the monitor

When the hub runs this monitor (`executors.kube_guard.enabled`, which
`GET /api/secrets` reports as `kube_guard`), the hub renews a share by default:

1. **One member renews.** A leader duty finds every hub-renewed share past half
   its token's lifetime (a 24-hour token at 12 hours, a 10-minute one at 5) and
   mints the next token, for the same lifetime, with a TokenRequest
   authenticated by the token the share holds. The self-renewal Role permits
   that and nothing else. The new kubeconfig differs from the old one only in
   the token (`kubeshare.ReplaceToken`), and it is sealed in place under the
   secret's own id, so every grant still points at it (`Broker.RenewSecret`).
   Each renewal writes a `secret.renew` row by `hub` naming both expiry times.
2. **Every member updates its sessions.** A monitor session holds the cluster
   credential it was minted from, and a run's session can outlive the token
   behind it. Once a minute, each member re-derives the minimised kubeconfig
   from the lease's grant for every live session that depends on a renewed
   share, the same way a [restored session](#a-hub-restarted-mid-run) is
   re-derived. `Registry.UpdateUpstream` swaps it in, and refuses any change
   other than a new bearer token: the server the session is pinned to, its CA,
   TLS name, proxy and client certificate must stay the same. The session keeps
   its connection pool, and the next request presents the new token. A run
   dispatched before the renewal keeps working after the token it started with
   has expired.
3. **Only the hub can use the renewal permission.** `serviceaccounts/token` is
   [refused for every verb](#subresources-that-are-not-data), so a sandbox under
   a write grant cannot mint itself a token, even when the grant's namespaces
   include the ServiceAccount's own and the cluster's RBAC would let the
   ServiceAccount do it (`TestTheMonitorNeverForwardsATokenRequest`).
4. **A self-renewing share is delivered only through the monitor.** As a file in
   a sandbox, it would be a credential that can extend itself. If the monitor is
   turned off later, the hub refuses the share's grants at dispatch, says so on
   the project's Activity tab, and keeps renewing the share for when the monitor
   is back.

A share is its owner's credential, and renewal keeps it alive. So the hub stops
renewing a personal share whose owner it denies, whether the person was
suspended or was offboarded with the secret kept under a legal hold. The hub
denies an owner who has a global deny role binding on their email or subject
(offboarding and a suspension through SCIM both write one), or who is a
provisioned user the identity provider deactivated. The second case covers a
suspension that resolved neither, which denies only a username or oid claim.
The share records why (`kube.renew_state:
stopped`, `kube.renew_error` naming the suspension, the hold's date and matter,
or the binding's reason), `cloop remote kube list` shows "stopped by the hub",
and the refusal is written as a `secret.renew` deny row, once per distinct
reason. A token pushed from a terminal does not keep the share alive either:
`cloop remote kube renew` is told so before it mints anything, and the hub
refuses the push (409). The check runs on every pass, so a reactivated owner's
share resumes; a token that expired in the meantime is lapsed. A share that is
not personal belongs to the organisation and is renewed whatever happens to the
person who made it, because offboarding keeps it.

A renewal that fails records why on the share (`kube.renew_error`, shown by
`cloop remote kube list`), and is audited once per distinct cause rather than
once a minute. If the token has already expired (the hub was down for more than
half its lifetime) or the cluster no longer accepts it (the ServiceAccount was
deleted), the share is marked **lapsed**: nothing the hub holds can
authenticate the next TokenRequest, so the renewal duty leaves it alone. Its
owner revives it with `cloop remote kube renew`, which mints the next token with
their own credentials.

### Without the monitor

A hub without the monitor would hand the share's token to the sandbox as a
file, and the self-renewal permission with it, so no self-renewal Role is
installed (`--renewal manual`, which a developer can also ask for on any hub).
The developer renews from the terminal: `cloop remote kube renew` mints a token
with their own credentials and posts it, together with where it was minted, to
`POST /api/secrets/{id}/renew`. The hub stores it only after the cluster has
authenticated it as the share's own ServiceAccount with a SelfSubjectReview. On
a cluster too old to answer one, only the token's claims are checked, and the
response says so. A run that already holds the old kubeconfig keeps it until
that token expires; the next dispatch gets the new one. Without the monitor, a
grant of the share is itself
[refused unless acknowledged](#without-the-monitor-refused-unless-acknowledged),
like any kubeconfig grant that names namespaces or verbs.

### What revoke and renew trust

`cloop remote kube revoke` and `renew` act on the cluster with the credentials
of whoever runs them, often a colleague or an administrator, on a share whose
metadata (including the context they default to) its uploader wrote. Without
the checks below, a `secret.grant` holder could upload a share listing
`ClusterRoleBinding/cluster-admin` among its objects and have an
administrator's revoke delete it, or name `kube-system`'s ServiceAccount and a
server of their own and have a colleague's renew mint a token for it and hand it
to the hub, which would then send it to that server to check. So:

1. **The hub decides first.** Before touching the cluster, both ask
   `GET /api/secrets/{id}/authorize?action=delete|renew` (the same checks the
   `DELETE` and the renewal apply) and stop if the hub refuses. A hub too old to
   answer counts as a refusal; `revoke --force` then deletes only the hub's
   secret.
2. **The context must reach the share's cluster.** The local context's API
   server must be the share's `kube.server`, and the CA it trusts must hash to
   `kube.ca_sha256`. Otherwise both refuse with an error naming `--context`,
   rather than act with the developer's credentials on another cluster. A share
   made with `--server` (the hub reaches the cluster at another address) is
   renewed and revoked through a context for that address.
3. **Revoke deletes only what the share created.** The candidates are what its
   plan creates, what its metadata lists and what carries its label in its
   namespaces. Each is read back from the cluster and deleted, by uid and
   resourceVersion, only if it carries `cloop.dev/kube-share=<id>` and a
   `cloop.dev/owner` annotation naming the share's owner (the hub's record, or
   for a personal share its owner), so an object changed after it was read is
   not deleted. Anything else is reported as "Not deleted, not this share's" and
   left alone, and a name no share could create never becomes a request. If a
   ServiceAccount by the share's name exists but is not the share's, the revoke
   fails and the share's tokens stay valid until they expire.
4. **Renew mints only for the share's own ServiceAccount.** It must be named as
   a share names it and read back from the cluster with the share's label and
   owner, or renew refuses before minting.
5. **A token goes only to the server that minted it.** The terminal posts the
   server and CA it minted at. Unless they are the stored kubeconfig's, the hub
   refuses without sending the token anywhere; only then does it ask that server
   to confirm the token.

### Revoking

`cloop remote kube revoke` asks the hub, then deletes the ServiceAccount first,
which at once invalidates every token ever minted for it (the hub's, a live
session's, any copy), then its RoleBindings and Role. It then sweeps the share's
namespaces for anything else carrying its label (each checked as above), and
only then deletes the hub's secret, which revokes its grants and closes the
monitor sessions that depend on them. A revoke the cluster cannot complete keeps
the secret so it can run again. `--force` deletes it anyway and names what is
left of the share's objects or, when the cluster was not touched, lists the
candidates with their owner annotation to check before deleting. It never
suggests deleting by label: anybody who can label objects could give theirs the
share's id.

### Proven on a cluster

`TestKubeShareWithAnExecPlugin` in [`tests/kube`](../../tests/kube/share_test.go)
runs on a kind cluster in CI, with a developer ServiceAccount holding `admin` in
three namespaces, a kubeconfig that signs in only through a fake exec plugin
(`v1`, relative command, `provideClusterInfo`), and a hub with the monitor on
and the host executor. The test:

1. shares with `--access write --ttl 10m` (the shortest token the API issues),
   and checks the objects and that RBAC alone would let the ServiceAccount mint
   its own token;
2. dispatches a run whose probe reads and writes through the monitor and is
   refused the ServiceAccount's own token, a raw TokenRequest for another, and
   `kube-system`;
3. has the probe, under that write grant, try a ServiceAccount token Secret, a
   Pod and a Deployment as another ServiceAccount, a `hostPath` Pod, a new image
   for a Deployment already running as another ServiceAccount, and a
   RoleBinding: each is refused and none exists afterwards, while a Pod as the
   default ServiceAccount passes;
4. waits for the hub's renewal and for the first token to expire, and has the
   same run read and write again;
5. revokes, finds no labelled object anywhere, and has the run confirm it is cut
   off;
6. uploads a crafted share (a token for a ServiceAccount the administrator made,
   an object named like the share's, a decoy labelled with its id by another
   owner, and metadata listing `cluster-admin`'s binding) and revokes it with a
   cluster-admin kubeconfig: nothing is deleted, the hub's secret is kept, and
   `--force` deletes only that.

It takes about thirteen minutes, most of it waiting for the first token to
expire.

---

## What it enforces, and what it does not

**Enforced, outside the sandbox, on every request:**

| | |
| --- | --- |
| Verb allowlist | `create`, `update`, `patch`, `delete`, `deletecollection` are refused under the default. |
| Namespace allowlist | Both directions: a named namespace outside the list, and a request that names none while a list exists. |
| Resource allowlist | When set, matched as RBAC spells it. |
| Non-resource URLs | Readable only, and only inside the allowlist; discovery by default. |
| Dangerous subresources | `exec`, `attach`, `portforward`, `proxy`, `ephemeralcontainers`, and the TokenRequest API `serviceaccounts/token`: refused for every verb, and not configurable. |
| Credentials minted by a write | A ServiceAccount token Secret, a workload running as a non-default ServiceAccount or reaching the node, a patch to one already doing either, RBAC writes and CertificateSigningRequests: refused under every grant. A body the monitor cannot read is refused for these kinds. See [writes that would mint a credential](#writes-that-would-mint-a-credential). |
| Protocol upgrades | Refused, both SPDY and websocket. |
| Impersonation | `Impersonate-*` headers removed, never forwarded. |
| Request body size | Limited to 3 MiB by default. A larger body is refused, not truncated: a declared `Content-Length` over the cap is rejected before a byte is read, and a chunked body that runs over is cut off with `body_too_large`. (Truncation made the API server answer with its own parse error, telling the sandbox its JSON was malformed when the request was only too large.) Under the default read-only policy, no request has a body at all. |
| Session lifetime | Bounded by the TTL, and revoked when the lease is released. |

**Not enforced:**

- **The cluster's RBAC is still the ceiling.** The monitor can only narrow it.
  If the granted credential cannot read `secrets` in `team-a`, a policy that
  permits it does not change that, and the API server's own 403 is passed back.
- **Response content is not filtered.** A permitted `get secrets` in a permitted
  namespace returns the secrets, including a ServiceAccount token Secret that
  somebody else created there earlier, which `edit` may read. The monitor
  decides which requests go through, not what comes back. Use `resources` and the
  namespace list to narrow what can be read.
- **The credential-minting checks only recognise the shapes listed above.** They
  miss a custom resource that names a ServiceAccount under a key other than
  `serviceAccountName` or `serviceAccount`, an admission webhook that rewrites
  Pods (cluster-scoped, so refused under a namespace list, but not under a grant
  without one), and a container that escalates through capabilities rather than
  `privileged`. Enforce at least the `baseline` Pod Security Standard on
  namespaces you grant write access to. A patch is checked against the object as
  it was read a moment before, so a concurrent change by someone else between the
  read and the patch is not caught.
- **Cluster-scoped reads are refused.** With a namespace allowlist in force,
  `get nodes` cannot be allowed; it is refused as `cluster_scope`. Use a second
  grant without a namespace list, limited by resource instead.
- **The glob intersection is conservative, so a floor can refuse a grant it
  overlaps.** A floor of `app-1` and a grant for `app-*` share `app-1`, but glob
  languages cannot be intersected in general, so the lease is refused rather than
  guessed at. This fails closed: the operator gets an error, not a gap. See
  [the floor](#the-deployment-floor-and-the-grant-intersect).
- **It does not cover a sandbox that reaches the cluster some other way.** The
  monitor governs the credential cloop delivers. A sandbox with a direct network
  route to an API server still has no credential for it, but if the cluster
  grants `system:anonymous` anything useful, only the network can block that
  path. Pair the monitor with
  [egress filtering](../reference/configuration.md#ip-layer-egress-filtering).
- **It does not govern the hub's own cluster credential.** The `kubernetes`
  executor leases a kubeconfig to create Pods through its own broker, which does
  not go through the monitor. The hub uses that credential itself and never
  delivers it into a sandbox, and a read-only monitor in front of it would stop
  the hub scheduling work. See
  [the `kubernetes` backend](executors.md#kubernetes--kind-kubernetes-isolation-remote).
- **A compromised hub is a compromised credential store.** Nothing here protects
  against that. The gain is that there is one store to protect instead of one
  per running sandbox. The monitor also adds a listener on the hub that
  everything on the sandbox network can reach, so bind `listen_addr` as narrowly
  as that network allows.

---

## Audit events and metrics

`Registry.OnEvent` receives every decision. Events carry identifiers, resource
names, namespaces and reasons. `kubeguard.Event` has no field that could hold
credential material or object content, so the events are safe to export to a
SIEM.

| Kind | Emitted when | Notes |
| --- | --- | --- |
| `request_denied` | policy refused a request | The most important row: the only record of a sandbox trying to write to or read outside its granted scope, or to mint itself a credential. Nothing else in cloop records it. Alert on it. |
| `request_allowed` | a request was forwarded | Off by default: a `kubectl get pods` is several requests and a watch is one that never ends, so a row per allowed request would bury the denials in discovery traffic. `executors.kube_guard.audit_allowed: true` turns it on, for a hub whose audit trail has to show what a sandbox *read*. |
| `session_minted` | a session was created | `Detail` carries the policy summary and the expiry. |
| `session_closed` | a session was revoked, released or reaped | `Detail` carries the reason and the allowed and denied counts. Also written for a session that ended while no hub process served it: one that was not restored with its run, or was retired after it lapsed. |
| `session_restored` | the hub process that adopted a run restored its session | `Detail` names the process that held it until then. |
| `rejected` | refused *before* a session was identified, or a hub-side failure | No credential, an unknown token, an expired or revoked session, or an unreachable cluster. Unlike `request_denied`, none of these reached a policy decision. |

`OnEvent` runs on the request goroutine, so a slow sink delays the sandbox's API
call. That is why the hub's own sink does a single insert.

The events are written to the same hash-chained `audit_events` table as the
credential broker's, with `entity_type` `kubeguard`, the session id as the
entity, and the kind prefixed: `kubeguard.request_denied`,
`kubeguard.request_allowed`, `kubeguard.session_minted`,
`kubeguard.session_closed`, `kubeguard.session_restored`, `kubeguard.rejected`.

```console
$ cloop audit-log list --entity kubeguard --since 7d
$ cloop audit-log list --type kubeguard.request_denied --since 30d --json
```

The payload carries the session, the cluster URL, the context, the verb, the
resource, the namespace, the object name, the deny reason, the project, task,
executor, grant and lease ids, and the prose detail, and nothing else. A failed
audit write does not fail the request; the decision goes to stderr instead,
prefixed `kube-guard:`.

A task doing what it was asked to do never produces a `request_denied`. Each one
is either a workload doing something it was not granted, or a policy narrower
than the task it was minted for. Both need a person to look at them.

### Metrics

Two counters are exported at `/metrics` (see [metrics](../operations/metrics.md)):

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_kubeguard_requests_total` | counter | `result`: `allowed` or `denied` |
| `cloop_kubeguard_denials_total` | counter | `reason` |

`reason` is one of `verb_not_allowed`, `namespace_not_allowed`, `cluster_scope`,
`resource_not_allowed`, `dangerous_subresource`, `non_resource_path`,
`protocol_upgrade`, `body_too_large` and `unauthenticated`, and, for a write that
would [mint a credential](#writes-that-would-mint-a-credential),
`service_account_token_secret`, `workload_service_account`, `host_access`,
`rbac_binding`, `rbac_role`, `certificate_signing_request` and
`unreadable_body`. The `request_denied` audit row carries the same reason.

A failure on the proxy side, such as an unreachable cluster or an unusable
credential, is counted as neither allowed nor denied, so a broken upstream does
not show up as policy refusals during the incident an operator is paged for.

**A workload expecting write access it was not granted:**

```promql
rate(cloop_kubeguard_denials_total{reason="verb_not_allowed"}[5m]) > 0.1
```

**Someone trying to get a shell in a pod** (this should stay at zero):

```promql
rate(cloop_kubeguard_denials_total{reason="dangerous_subresource"}[5m]) > 0
```

**A workload trying to get a credential of its own** (this should also stay at
zero):

```promql
sum(rate(cloop_kubeguard_denials_total{reason=~"service_account_token_secret|workload_service_account|host_access|rbac_binding|rbac_role|certificate_signing_request"}[5m])) > 0
```

---

## Troubleshooting

**`Unable to connect to the server: x509: certificate signed by unknown
authority`** — the delivered kubeconfig's `certificate-authority-data` does not
match what the monitor presents. Set `ca_file` to the issuing CA's PEM. When it
is empty the hub embeds `cert_file` itself, which is right for a self-signed
certificate but not for one signed by a private CA whose chain matters. Under
`tls: auto` the two cannot disagree. There, the equivalent failure is
**`x509: certificate is valid for …, not …`**, which means the leaf certificate
does not name the host the kubeconfig's `server:` points at. The hub issues a
leaf for the `advertise_url` it starts with, so restart it after changing that,
and run `cloop hub doctor` (`kubeguard.tls`).

**`Unable to connect to the server: dial tcp … connect: connection refused`** —
`advertise_url` names an address the sandbox cannot reach. The hub logs the
address it advertises at startup; compare it with what the sandbox can resolve
and route to. This is the most common deployment mistake, because everything on
the hub side works.

**`the server could not find the requested resource`, on every command** — a
custom `non_resource_paths` list leaves out discovery. Remove the override and
let the default set apply, or include at least `/api`, `/api/*`, `/apis`,
`/apis/*` and `/apis/*/*`.

**`this session has read-only access to the cluster, so it may not create …`** —
the monitor is working as configured. Either the grant names no `--verbs`, which
means read-only, or the intersection with the hub-wide floor left only read
verbs. If the task needs to write, widen the grant or the floor.

**`pods without a namespace would read across the whole cluster; this session is
confined to team-a, so name one with -n`** — a `--all-namespaces` read, or a
cluster-scoped resource, under a namespace-confined grant. Pass `-n`, or issue a
second grant for the cluster-scoped part.

**`pods/exec is not readable through the cloop Kubernetes monitor`** — the
`exec` subresource is refused for every verb, and this cannot be configured. A
workload that needs to exec into pods needs a kubeconfig grant on a hub without
the monitor.

**`serviceaccounts/token is refused by the cloop Kubernetes monitor for every
verb, under every grant`** — `kubectl create token`, or anything else asking the
TokenRequest API for a credential, from a sandbox. The token would bypass the
monitor from then on. A workload gets the access its grant gives it, through the
monitor, and no credential of its own.

**`kubeconfig grant constraints cannot be enforced without the Kubernetes access
monitor`** — a grant naming namespaces or fewer than every verb, on a hub with
`executors.kube_guard` off. [Turn the monitor on](#turning-it-on)
(`enabled: true`, `tls: auto`). If delivering the credential unenforced is
acceptable, have an administrator run
`cloop hub grant unguarded <grant-id> --reason <why>`. `cloop hub doctor` lists
every such grant.

**`… is refused by the cloop Kubernetes monitor: it names ServiceAccount …`**,
**`… it mentions "kubernetes.io/service-account-token" …`**, **`… it asks for a
hostPath volume …`**, **`… under every grant: a binding hands …`** — a write that
would give the workload a credential of its own (see
[writes that would mint a credential](#writes-that-would-mint-a-credential)).
Run the workload as the namespace's default ServiceAccount, and have a cluster
administrator create RBAC objects, workloads that run as named ServiceAccounts,
and node-level workloads.

**`… the object already runs as ServiceAccount … and a patch keeps that`** — a
change to a workload that somebody else set up to run as its own ServiceAccount.
Make the change as a cluster administrator.

**`… cannot read this one (it is sent as application/vnd.kubernetes.protobuf)`** —
a client is configured to send writes as protobuf. Use JSON
(`--kube-api-content-type application/json`, or client-go's default).

**`kubeconfig … is a share the hub renews, so its ServiceAccount may create
tokens for itself, and it is delivered only through the Kubernetes access
monitor`** — a self-renewing [share](#kubernetes-shares-a-cluster-behind-a-credential-plugin)
granted on a hub that delivers kubeconfigs without the monitor. Turn the monitor
on, or share the cluster again with `--renewal manual`.

**`cloop remote kube revoke` or `renew`: `the context reaches …, and the share is
for …`** or **`the context trusts another CA`** — the context (by default the one
the share was made from, as named in its metadata) does not reach the share's
cluster. Pass `--context` with one that does. For a share made with `--server`,
use a context for the address the hub uses.

**`Not deleted, not this share's: …`** — revoke found an object it was asked
about, or one carrying the share's label, that the cluster does not show as the
share's own: it has no label, another share's label, or an owner annotation that
is not the share's owner. The object is left alone. If the share's
ServiceAccount is among them, the revoke fails and keeps the hub's secret, and
the share's tokens are still valid. Check who created the ServiceAccount before
deleting anything.

**`cloop remote kube list` shows a share as `stopped by the hub`** — its owner is
denied on the hub: suspended at the identity provider, offboarded with the
secret kept under a legal hold, or blocked by a deny role binding. The line under
the table says which. Renewal resumes when the deny is lifted.

**`cloop remote kube list` shows a share as `hub, failing`** — read the
`the last renewal failed:` line under the table. `may not create its own token:
its self-renewal Role or RoleBinding (…-renew) is missing or was changed` means
somebody edited the Role; recreate the share, or renew it by hand. A share shown
as `lapsed` expired before the hub could renew it, because the hub was down for
more than half the token's lifetime or the ServiceAccount was deleted. Only
`cloop remote kube renew` (or, if the ServiceAccount is gone, `revoke --force`)
moves it on.

**`asked to upgrade the connection`** — `kubectl exec`, `attach`, `port-forward`
or `proxy`, or a client configured to watch over websockets. Ordinary watches
(`kubectl get -w`) work without any change.

**`this cloop Kubernetes session has expired; the hub issues a fresh one at the
start of each dispatch`** — the run outlived `session_minutes`. Raise it (the
ceiling is 720) or shorten the task. The token itself was correct, which is why
this message differs from the unauthenticated one.

**`no valid cloop Kubernetes session: the credential is missing, unknown, or has
been revoked`** — the lease was released, nothing is sending the token, or the
hub restarted and did not restore the session. A session is not restored if its
run was not adopted within 60 seconds of the request, or if the restore refused
it because its grant was revoked or expired while the hub was down, or because
it lapsed. The caller is not told which; the session's
`kubeguard.session_closed` row says.

**A lease fails with `executors.kube_guard is enabled but the Kubernetes access
monitor is not running`** — the section is enabled and the monitor failed to
start. The hub logged why at startup. It refuses the lease rather than falling
back to delivering the credential. The run starts without the kubeconfig, and
says so on the project's Activity tab as a `credential_refused` event naming the
run.

**`secret_files[N] repeats path …/kubeconfig`** — an older hub is delivering two
kubeconfig grants to one project. A current hub merges them into one document
([several grants, one document](#several-grants-one-document)).

**`grant … cannot be honoured under this hub's kube_guard policy …`** — the
hub-wide floor and the grant have nothing in common on some dimension. The end
of the message says which: `policy permits no verbs` for the verbs, or
`namespaces: the grant asks for … but this hub's policy floor allows only …` for
a glob list. Every dimension refuses rather than falling back to a default.
Widen the floor, or narrow the grant to a literal subset of it; see
[the floor](#the-deployment-floor-and-the-grant-intersect).

**The delivery is not monitored at all** — `cloop secret lease` shows the
material without `via monitor`. Either `executors.kube_guard.enabled` is false,
or the lease was built by a path that does not attach the monitor. The hub's
startup line tells you which.

---

## See also

- [Component and security architecture](README.md): the monitor among the
  hub's other credential guards
- [Security model](../security/model.md): the trust boundaries and the
  guarantee → test table
- [Threat model](../security/threat-model.md): STRIDE per boundary, with the
  residual-risk column
- [Git interception proxy](../git-interception-proxy.md): the same approach for
  git, and the package this one is modelled on
- [Secret and egress grants](../guides/secrets.md#kubeconfig): how the
  kubeconfig the monitor holds is granted in the first place
- [Executor architecture](executors.md): where a sandbox comes from, and the
  hub's own cluster credential
- [Configuration](../reference/configuration.md#kubernetes-access-monitor):
  `executors.kube_guard` alongside the other executor sections
- [`pkg/kubeguard/policy.go`](../../pkg/kubeguard/policy.go): the decision this
  page describes
