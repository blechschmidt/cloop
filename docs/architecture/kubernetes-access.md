# Kubernetes access monitor

How a sandbox is allowed to read one namespace of a cluster and nothing else,
without ever holding a credential that could reach the rest of it.

`pkg/kubeguard` is a Kubernetes API interception proxy that runs **outside** the
sandbox. The sandbox's `KUBECONFIG` points at it, the sandbox authenticates with
an ephemeral bearer token, and the monitor — holding the real cluster credential
— parses every request into the tuple an authorization decision is actually
about (verb, API group, resource, subresource, namespace, name), matches it
against the grant, and only then presents the credential upstream. The namespace
allowlist stops being a default `kubectl` can ignore and becomes a property of
the network path. "Read-only", which a kubeconfig has no field for at all, starts
existing.

The monitor runs **inside the hub process** and is **off by default**. Without
it, a kubeconfig grant that names namespaces, or fewer verbs than all of them —
read-only, the default, above all — is **not delivered** (Task 20420): nothing
would enforce what it says, as [the hole it closes](#the-hole-it-closes)
describes. An administrator may acknowledge delivering one anyway, on the
record ([without the monitor](#without-the-monitor-refused-unless-acknowledged)).
Setting `executors.kube_guard.enabled: true` turns the monitor on, and from then
on every kubeconfig grant the hub delivers is a monitor session instead. See
[turning it on](#turning-it-on).

This is the same bargain the [git interception proxy](../git-interception-proxy.md)
makes for git, and the two packages are deliberately shaped alike.

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

Without the monitor a kubeconfig grant can only be delivered by rewriting the
document. `MinimizeKubeconfig`
drops every context outside `--contexts`, pins each survivor to an allowed
namespace, and removes the clusters and users nothing references any more,
credentials included. See [the secrets guide](../guides/secrets.md#kubeconfig).

That is real, and for the question "**which clusters** may this project reach"
it is sufficient: a sandbox cannot reach a cluster whose credential it was never
handed. It cannot do the other two things the grant appears to promise.

### The namespace is a client-side default

The `namespace:` field of a kubeconfig context is the value `kubectl` uses when
you do not pass `-n`. It is not a bound. A workload granted `--namespaces
team-a` receives a document that says `namespace: team-a`, and then:

```console
$ kubectl get pods                       # team-a, as configured
$ kubectl -n kube-system get secrets     # also works
$ kubectl get pods --all-namespaces      # also works
```

Nothing in the second and third commands is unusual or adversarial-looking —
`-n` is the flag every Kubernetes user reaches for first. Until this package
existed, "this project may only touch namespace `team-a`" was a sentence written
on the honour system, enforced by nothing, and the first evidence that it had
been ignored would have been the effect rather than the attempt.

### Read-only cannot be written down at all

There is no field in a kubeconfig for it. A kubeconfig carries a *credential*,
and a credential's authority is whatever the cluster's RBAC says it is — which
the hub does not administer and generally cannot narrow.

This matters more than it sounds, because of where these documents come from. A
kubeconfig in a cloop secret store is usually the one a developer already had:
the file their own cluster administrator issued them, frequently bound to a
`ClusterRole` with rather more in it than `get pods`, and not uncommonly
`cluster-admin`. Granting it to a project with `--namespaces team-a` delivered
that authority into a sandbox and asked it not to use most of it.

Both gaps need something that reads each request and decides, and that something
must live **outside** the sandbox — anything inside it is advice to code under no
obligation to take it. So: the hub keeps the credential, the sandbox gets a
token worth only what the policy allows, and every request passes through a
process the sandbox does not control.

---

## Without the monitor: refused, unless acknowledged

Until Task 20420 a hub with no monitor delivered the minimised kubeconfig
whatever the grant said, so a grant reading "read-only, namespace `app`" handed
the workload everything the kubeconfig's identity may do, and nothing anywhere
said so at the moment it happened. Now the broker refuses it
(`ErrKubeConstraintsUnenforced`, `pkg/secretbroker/material.go`), the way a
GitHub branch allowlist is refused without the git proxy:

```console
secretbroker: kubeconfig grant constraints cannot be enforced without the Kubernetes access
monitor: grant grant_1a2b… limits kubeconfig dev-kube to namespaces app and read-only access
(get, list, watch), which only cloop's Kubernetes access monitor enforces, and this hub runs
none … It is not delivered — enable executors.kube_guard (enabled: true, tls: auto), or have an
administrator acknowledge delivering it unenforced with `cloop hub grant unguarded grant_1a2b…
--reason <why>`
```

What counts is `Constraints.KubeMonitorOnly`: a namespace list that confines
(anything but `*`), and a verb list short of all eight — the empty list is
read-only and claims the most. A grant naming only contexts **and** every verb
claims nothing a monitor enforces (contexts are enforced by minimisation), so it
is delivered as before. The refusal reaches the project like any other refused
credential: named on the lease (`Lease.Refused`) and journaled per run.

It is a rule about delivery into a workload. The `kubernetes` executor's own
cluster credential — the grant `--to executor:<id>` it creates Pods with — is
leased by a broker of the executor's own and used in the hub process
([never routed through the monitor](#what-it-enforces-and-what-it-does-not)), so that
lease says so (`Requester.KubeInProcess`) and is not refused; workspace
provisioning, which reads only GitHub tokens out of the same subjects' lease,
says the same. A *run* on that executor matches the same grant, and its lease
is refused like any other.

The fix is the monitor. The exception is an administrator's acknowledgement,
recorded **on the grant** — who, when and why:

```bash
cloop hub grant unguarded grant_1a2b3c --reason "throwaway lab cluster, no monitor yet"
cloop hub grant unguarded grant_1a2b3c --withdraw
```

or the **Acknowledge unguarded** button on the grant's row in the Secrets panel
(`POST`/`DELETE /api/grants/{id}/unguarded`, `user.manage`). A reason is
required. Recording or withdrawing one is its own audit row,
[`secret.unguarded_ack`](../reference/audit-events.md#secret) /
`secret.unguarded_withdraw`; every lease that delivers such a grant says
"unguarded: … not enforced, acknowledged by …" in its summary; the Secrets
panel badges the row (`kube_delivery`: `refused`, `acknowledged`, `monitor`,
`monitor_down`, `unconstrained`, `monitor_required`); `cloop hub grant list`
lists every acknowledged grant below the request queue, and `--grants` lists
every grant with what it amounts to without the monitor. `cloop hub doctor`
**fails** while an unacknowledged grant like this exists on a hub with the
monitor off, and warns while an acknowledged one does.

Two things no acknowledgement changes: a hub that asked for the monitor
(`executors.kube_guard.enabled`) and is not running one refuses every kubeconfig
(`ErrGuardUnavailable`), and a [share the hub renews](#renewal-through-the-monitor)
is delivered only through the monitor, because its ServiceAccount may mint its
own tokens.

---

## The inversion

```
sandbox ──session token──▶ kubeguard ──cluster credential──▶ API server
                              │
                     Policy.Decide per request
```

The monitor is shaped like a reverse proxy, and the interesting part is what it
refuses to be (`pkg/kubeguard/proxy.go`):

- **The destination is never taken from the request.** It comes from the
  session, which came from a kubeconfig the hub holds. No header, path or `Host`
  can point the monitor at another cluster.
- **The credential is attached in one place**, after the decision, and it is
  `Set` rather than added — so nothing the sandbox sent survives into the
  credential slot. An upstream with no credential at all leaves with no
  `Authorization` header, not with whatever the sandbox supplied.
- **Impersonation headers are stripped.** Kubernetes lets a sufficiently
  privileged credential act as another user, and a developer's own kubeconfig
  frequently is one, so forwarding `Impersonate-User` would hand the sandbox
  every identity in the cluster through a header.
- **Hop-by-hop headers are dropped** in both directions, per RFC 7230, so
  `Connection` cannot be used to smuggle a header past the upstream.
- **A protocol upgrade is refused before it reaches the transport**, so the
  monitor never holds a stream it cannot read.

A refusal is rendered as a Kubernetes `Status` object rather than a bare 403,
which is what makes the whole thing usable: `kubectl` parses it and prints the
message, so a developer sees

```console
$ kubectl delete pod web-0
Error from server (Forbidden): this session has read-only access to the cluster,
so it may not delete pods (allowed: get, list, watch)
```

### What the sandbox holds

One file, mode `0600`, in the lease directory, pointed at by `KUBECONFIG`:

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

What is **not** in it is the point: no bearer token for the cluster, no client
certificate, no client key, no CA for the cluster, and not even the cluster's
address. A sandbox holding this file cannot reach the API server at all except
through the monitor, because it does not know where the API server is.

The `namespace:` line is still a client-side default, and still ignorable — it
just no longer matters, because the monitor enforces the allowlist on every
request regardless of what the context says. It is set to a namespace the policy
actually permits (the minimised context's, if allowed, otherwise the first
non-glob entry of the allowlist) so that `kubectl get pods` works without `-n`.

The environment the workload sees alongside it, none of it a credential:

```
KUBECONFIG=<lease dir>/kubeconfig
CLOOP_K8S_NAMESPACE=team-a
CLOOP_K8S_ALLOWED_NAMESPACES=team-a
CLOOP_K8S_VERBS=get,list,watch
CLOOP_KUBEGUARD_SESSION=<session id>
```

`CLOOP_K8S_VERBS` is a courtesy so a harness can decline to attempt a write it
would be refused; it is not a control. `CLOOP_KUBEGUARD_SESSION` is how lease
release finds the session again to revoke it, and the session id is not secret —
it is the first half of the token and appears on every audit row.

### Several grants, one document

A lease can carry more than one kubeconfig grant — two clusters, one cluster
granted twice with different namespaces or verbs, an edited assignment whose
predecessor is not revoked yet. Every monitor-issued document names its cluster,
user and context `cloop` and every grant renders its file as `kubeconfig`, so
until Task 20413 two grants rendered two files at one path: a delivered lease
was refused (`secret_files[N] repeats path …/kubeconfig`) on containers, devices
and Pods, and on the hub one document overwrote the other. The broker now merges
them (`pkg/secretbroker/kubemulti.go`) into **one** document with a context per
grant:

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

**One document rather than one file per grant listed in `KUBECONFIG` with `:`**,
because `KUBECONFIG` has to stay a path. kubectl and client-go merge a list, but
a program that passes `$KUBECONFIG` to `clientcmd.BuildConfigFromFlags`, a
script that opens it, an agent that `cat`s it and the hub doctor's own smoke
workload (`[ -f "$KUBECONFIG" ]`) read it as one file name; and an edge agent
relocates a lease's files by rewriting each variable's leading directory, which
would move only a list's first entry — on every agent already deployed — and
kubectl skips a missing file without a word. One document also states
`current-context` instead of leaving it to kubectl's first-file-wins rule.

- **Names** come from each grant's secret, sanitised to lower-case letters,
  digits and `-`, with `-2`, `-3` on a collision. Every reference is renamed
  through its own document, so a context that named a user its document did not
  define names nothing in the merged one either — never another grant's user
  that happened to share the name.
- **`current-context`** is the narrowest grant's: every namespace named before a
  pattern, before cluster-wide; read-only before read-write; fewer namespaces;
  then secret name and grant id. The order is total, so the document is a
  function of the grants: whatever order the materials arrive in, at dispatch or
  in the process that adopts the run, it renders the same.
- **Monitored and unmonitored grants mix.** A grant the monitor holds is an entry
  pointing at the monitor with its session token; one it declined is its
  minimised document's own clusters, users and contexts.
- **The environment.** One grant renders exactly the variables above. With
  several, those describe the grant behind `current-context`, and
  `CLOOP_K8S_CONTEXTS` (every context, current first), `CLOOP_K8S_GRANTS` (a JSON
  array: each grant's contexts, secret, namespaces, verbs, and whether and under
  which session the monitor holds it) and `CLOOP_KUBEGUARD_SESSIONS` describe
  them all. These belong to the lease, not to any one grant, so withdrawing a
  grant does not scrub a description the others still need.
- **Withdrawing one grant** ([Task 20403](../guides/secrets.md#revoking-a-grant))
  takes exactly its access when the monitor holds it: its entry is a session
  token, and closing the session is the withdrawal — the document stays. An
  unmonitored grant's entry is the cluster credential itself, and no path can
  cut one entry out of a file a workload may have open, so the document is filed
  under every unmonitored grant and goes with any of them. With every grant
  monitored it is filed under the narrowest, whose withdrawal takes it too: some
  grant's binding has to name the file, or no delivery path would know the
  workload needs one. Both err toward less access.
- **A restart.** The monitor is given each grant's minimised document under the
  grant's own names, before the merge renames anything, and records the
  session's context by that name. The process that adopts the run re-derives
  exactly that document from the grant ([below](#a-hub-restarted-mid-run)), so
  each session is restored under the token the merged document already holds.

### What the hub holds

A `kubeguard.Session` per delivery, in memory: the parsed cluster credential
(unexported, never serialised — `Session` has no `MarshalJSON` and every
exported field on it is safe), the policy, the attribution labels, and a
**SHA-256 of the bearer token**. The token itself exists in exactly one place
after minting: the kubeconfig delivered into the sandbox. A dump of the hub's
memory or a leak of the session struct yields nothing that can authenticate.

Authentication is a constant-time compare of the full token's hash, and an
unknown session id is hashed anyway before being rejected, so timing does not
distinguish "no such session" from "wrong token". Both return the same error,
for the same reason: telling them apart is an oracle for enumerating live
sessions.

The kubeconfig is parsed by `pkg/executor/kubernetes.ParseKubeconfig` rather
than a parser of kubeguard's own, so the three refusals that already guard a
tenant-supplied kubeconfig apply here too and cannot drift apart from the
driver's: an `exec` credential plugin, an `auth-provider` block, and a
credential that points at a file path on the control-plane host. A cluster whose
kubeconfig signs people in through a plugin — AKS, EKS, GKE — is shared through
a ServiceAccount instead, minted from the developer's own terminal; see
[Kubernetes shares](#kubernetes-shares-a-cluster-behind-a-credential-plugin).

**What it writes down (Task 20383).** Each session is also recorded in
`proxy_sessions` — its id, the token's SHA-256, the cluster URL, the context, the
policy, the lease and grant it stands on, the run, and which hub process serves
it — so the process that adopts a run after this one stops can restore it. Never
the token, and never the cluster credential: a restored session re-derives the
kubeconfig from the lease's grant. See [a hub restarted mid-run](#a-hub-restarted-mid-run).

### What a leaked session token is worth

| Leaked | Worth |
| --- | --- |
| **Session token** | Exactly the policy, for the remaining TTL, against **one** cluster, through **one** monitor. Under the default: get, list and watch, in the granted namespaces, with no exec, no port-forward, no writes, and nothing at all once the TTL lapses or the lease is released. Meaningless against the API server directly — it is not a credential the cluster has ever heard of. |
| **Kubeconfig delivered into the sandbox** — what an un-configured hub still does for a grant that claims every verb in every namespace, or that an administrator [acknowledged](#without-the-monitor-refused-unless-acknowledged) | Whatever that cluster's RBAC grants the uploading user, which on a personal kubeconfig is frequently cluster-admin: every namespace, every verb, `exec` into any pod, from anywhere on the network, until somebody rotates the credential — which means rotating it for the human it belongs to as well. |

Two sharper points follow:

- **Detection.** The session version leaves a `kubeguard.request_denied` row on
  the *attempt*. The kubeconfig version leaves whatever the cluster's own audit
  policy happens to record about a *success*, attributed to the developer whose
  credential it was.
- **Revocation.** Releasing the lease cuts the session at the next request, with
  no cluster round-trip and no coordination. Revoking a delivered kubeconfig
  means rotating a credential in the cluster and re-issuing it to its owner.

---

## What a request is, and how it is decided

### The tuple

`pkg/kubeguard/apirequest.go` turns an HTTP method, path and query into an
`APIRequest`: verb, API group, API version, resource, subresource, namespace,
name — plus whether it is a resource request at all, and whether the client
asked to switch protocols. It is a pure function with no I/O, and it is the
security boundary of the package: everything the policy decides, it decides
about this struct.

The parse deliberately mirrors the API server's own `RequestInfoFactory`. Not
out of deference — if the monitor's idea of "which namespace is this request
about" differs from the cluster's by even one path shape, the difference *is* the
vulnerability. A request the monitor reads as namespace `team-a` and the cluster
reads as `kube-system` is a bypass that would look like a working allowlist
right up until it was not. So:

- repeated slashes collapse, and `.`/`..` segments are resolved before anything
  is matched — `/api/v1/namespaces/team-a/../kube-system/secrets` does not parse
  as `team-a`. `net/url` has already percent-decoded the path by then, so a
  `%2e%2e` arrives as `..` and is handled at the point it becomes one;
- `/api/v1/namespaces/team-a` is a request about the namespace *object*, and the
  namespace is also `team-a` — both readings are recorded, and they are not in
  conflict;
- a path that is not recognised as a resource request becomes a **non-resource**
  request rather than an error, which the policy then evaluates against the
  non-resource allowlist and denies by default.

### Method to verb

| HTTP | Names an object | Verb |
| --- | --- | --- |
| `POST` | — | `create` |
| `PUT` | — | `update` |
| `PATCH` | — | `patch` |
| `DELETE` | yes | `delete` |
| `DELETE` | no | `deletecollection` |
| `GET` / `HEAD` | yes | `get` |
| `GET` / `HEAD` | no | `list` |
| `GET` / `HEAD` with `watch=true` | either | `watch` |
| anything else | — | the lowercased method, so the denial can name it |

Two of these are load-bearing. `DELETE` without a name is `deletecollection`,
not `delete`: calling it `delete` would let an allowlist that permits removing
one object permit emptying a namespace. And `watch` is a verb of its own, as it
is in RBAC, so a policy that allows `get` and `list` but not `watch` is one
somebody can write and have honoured.

Non-resource URLs use RBAC's other spelling — `get`, `post` — because that is
how `nonResourceURLs` rules are written, and the difference is preserved rather
than smoothed over.

### The order of the checks

`Policy.Decide` runs seven checks, in an order chosen for the message the
operator reads rather than for speed: the most specific and most alarming reason
wins.

1. **A dangerous subresource**, or the TokenRequest API, whatever the verb.
2. **A write to RBAC or to a CertificateSigningRequest**, under every grant.
3. **A protocol upgrade.**
4. **A non-resource URL** — readable only, and only if it is in the allowlist.
5. **The verb.**
6. **The resource.**
7. **The namespace.**

A write that passes all seven and could [mint a credential by what it
contains](#writes-that-would-mint-a-credential) is then read, and decided by its
body.

### Subresources that are not data

Five subresources are refused for **every** verb and cannot be opted back into
by any policy:

| Subresource | What it actually is |
| --- | --- |
| `exec` | a shell inside the pod |
| `attach` | a shell on a process already running in it |
| `portforward` | a tunnel to anything the pod can reach, which on a cluster network is usually everything |
| `proxy` | arbitrary requests to the kubelet or a Service, laundered through the API server's credential |
| `ephemeralcontainers` | a new container inside a Pod already running — as whichever ServiceAccount that Pod runs as, with its token mounted (Task 20420); `edit` carries it |

This is the single most important rule in the package, because the obvious
implementation is wrong in a way that looks right:

```
GET /api/v1/namespaces/team-a/pods/web-0/exec?command=sh
```

A verb-only allowlist of `{get, list, watch}` **admits** that request. The method
is `GET`, the request names an object, so the verb is `get`. The API server
answers it by upgrading the connection and handing the caller a shell. "Read-only"
would have meant remote code execution on the cluster.

An operator who genuinely wants a sandbox to exec into pods does not want the
monitor in that path; they want a grant without it.

One more is refused on the same terms, for a different reason: **`serviceaccounts/token`**,
the TokenRequest API (Task 20416). It does not open a session; it answers with a
token for the cluster itself, which would never pass through the monitor again
and would last as long as the caller asked. A write grant's `create` admits it as
readily as it admits a configmap, so it is refused for every verb under every
grant — and it has to be: a [self-renewing
share](#renewal-through-the-monitor)'s ServiceAccount may create its own token,
which is how the hub renews it, and that permission must be the hub's alone.

```console
$ kubectl -n cloop-shares create token cloop-aks-dev-3f9c2a1b
error: failed to create token: serviceaccounts/token is refused by the cloop Kubernetes monitor
for every verb, under every grant: it answers with a token for the cluster itself, which would
never pass through this monitor again. …
```

### Writes that would mint a credential

The verb check cannot tell a ConfigMap from a credential, and a write grant holds
`create` on both. Before Task 20420 the monitor refused only
`serviceaccounts/token`, and a workload that may write a namespace — the `edit`
role may create Secrets, Pods and Deployments — could still give itself a
ServiceAccount credential that never passes through the monitor, that no grant's
TTL bounds and that a revocation does not reach:

| What the workload writes | Why it is a credential | Refusal |
| --- | --- | --- |
| a Secret of type `kubernetes.io/service-account-token`, or a write touching the `kubernetes.io/service-account.name`/`.uid` annotations | the token controller fills it in with a non-expiring token for the named ServiceAccount | `service_account_token_secret` |
| a Pod, PodTemplate, ReplicationController, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job or CronJob naming a `serviceAccountName` (or the deprecated `serviceAccount`) other than `default` | the cluster mounts that ServiceAccount's token into the container, which prints it to its log | `workload_service_account` |
| any custom resource (an API group the API server does not serve itself, one under `k8s.io` included: the Gateway API's are CRDs too) naming such a `serviceAccountName` | Tekton's TaskRuns, Argo's Workflows, Flux's Kustomizations act as the ServiceAccount they name | `workload_service_account` |
| a workload asking for `hostPID`, `hostIPC`, `hostNetwork`, a privileged container or a `hostPath` volume | on the node sit every Pod's token and the kubelet's own credential | `host_access` |
| a **patch** to a workload that already runs as another ServiceAccount, or already reaches the node | a patch keeps every field it does not mention: a new image for the deployer's Deployment runs the attacker's code as the deployer | `workload_service_account` / `host_access` |
| any write to a RoleBinding or ClusterRoleBinding | binds some subject — the namespace's default ServiceAccount, which any Pod runs as — to more | `rbac_binding` |
| any write to a Role or ClusterRole | changes what every subject already bound to it may do | `rbac_role` |
| any write to a CertificateSigningRequest, its approval or status | a signed client certificate is a credential for the cluster | `certificate_signing_request` |

A Pod as the namespace's `default` ServiceAccount passes, as does everything not
in this table.

**How the body is read** (`pkg/kubeguard/inspect.go`). Only writes to the
resources above are read — `create`, `update` and `patch` of the resource itself;
a subresource's body (a Scale, a Status) cannot change who a workload runs as. The
body is read whole, up to the session's body cap, judged, and then forwarded byte
for byte. JSON is walked token by token, so **every** occurrence of a repeated key
is checked rather than whichever one a decoder keeps; YAML (`application/yaml`,
server-side apply) is decoded with a parser that refuses repeated keys, bounds
aliasing and depth, and whose YAML-1.2 `yes` is treated as the YAML-1.1 `true` the
API server's decoder reads. A JSON patch is judged by each operation's path and
value, and a `copy` or `move` on a workload is refused, since what it writes comes
from elsewhere in the object. A **patch** to a workload is judged against the
object it patches too: the monitor reads it with the session's credential first,
and a patch to one that already runs as another ServiceAccount is refused. A body
the monitor cannot read — protobuf, CBOR, a compressed body, malformed JSON — is
refused (`unreadable_body`) rather than forwarded; kubectl, Helm and client-go send
JSON by default.

```console
$ kubectl -n team-a create -f pod-as-deployer.json
Error from server (Forbidden): error when creating "pod-as-deployer.json": create pods is refused
by the cloop Kubernetes monitor: it names ServiceAccount "deployer" (serviceAccountName), whose
token the cluster would hand the workload — a credential outside this monitor, which no
revocation reaches. Workloads created through it run as the namespace's default ServiceAccount
```

Each refusal is its own `reason` on the
[`kubeguard.request_denied`](../reference/audit-events.md#kubeguard) row and its
own label on `cloop_kubeguard_denials_total`. The price is real and deliberate: a
Helm chart that creates its own ServiceAccount, Role and RoleBinding, or a
Deployment that runs as a named ServiceAccount, cannot be installed through the
monitor. Install those as a cluster administrator; run the workload's own work
through the grant.

### Protocol upgrades

Every upgrade the Kubernetes API offers a client is a streaming session: SPDY for
exec, attach and port-forward, websockets for those plus watch. The first three
are already gone by subresource. That leaves websocket watch — the only
legitimate upgrade a read-only session could want — and `kubectl` does not use
it, because client-go watches over chunked HTTP/1.1 and HTTP/2, which the monitor
forwards unchanged and flushes as it goes.

So refusing every upgrade costs a capability nothing in the normal path uses, and
buys a boundary that does not depend on getting hijacked-connection accounting
right for a bidirectional stream the monitor cannot parse. A tunnel the monitor
cannot read is a tunnel the monitor is not monitoring.

**`kubectl get pods -w` works.** `kubectl exec`, `kubectl attach`,
`kubectl port-forward` and `kubectl proxy` do not, by design.

---

## The policy

One session's policy is five fields (`pkg/kubeguard/policy.go`): four allowlists
and a ceiling. What an empty list means differs per dimension, and the
differences are the interesting part.

| Field | Empty means | Matching |
| --- | --- | --- |
| `verbs` | **read-only** (`get`, `list`, `watch`) | exact, from RBAC's eight |
| `namespaces` | no namespace confinement | glob (`path.Match`, `*` admits all) |
| `resources` | every resource | glob against `resource` (core group) or `group/resource` |
| `non_resource_paths` | the discovery set below | glob, plus a trailing `/**` for any depth |
| `max_body_bytes` | 3 MiB | — |

Each list is capped at 256 patterns, each pattern at 256 characters, and a
pattern containing `..` or one `path.Match` cannot parse is refused rather than
stored.

**An empty verb list is the whole point of the package.** A grant that names a
cluster and says nothing about verbs gets read access, not the credential's own
authority. That is the one place in the constraint model where an empty list is
neither "allow all" nor a validation error, and the asymmetry is deliberate: the
safe reading of silence about a cluster credential is that nobody asked for the
ability to change anything.

**Resource patterns match without the subresource**, so `pods` admits
`pods/log`. A subresource is governed by the verb and by the dangerous-subresource
rule, not by this list.

**The default non-resource set is discovery**, and it is not optional in
practice:

```
/  /api  /api/*  /apis  /apis/*  /apis/*/*  /version  /openapi/**
/healthz  /readyz  /livez
```

Without these a read-only session is not read-only, it is broken. `kubectl get
pods` begins by fetching `/api` and `/apis` to learn which groups exist, then
`/api/v1` to learn that pods are namespaced; denying discovery produces "the
server could not find the requested resource" on every command, which reads as a
cluster problem rather than a policy one. None of these paths returns cluster
data — they are group names, type schemas, a build version and "ok".

### Namespace confinement is two refusals, not one

When a namespace allowlist exists, the monitor refuses:

- a request naming a namespace **outside** it — the case everyone pictures,
  `kubectl -n kube-system get secrets`;
- a request naming **no namespace at all**. `kubectl get pods -A` and `GET
  /api/v1/secrets` are collection reads spanning the whole cluster. Letting them
  through on the grounds that "no namespace was named, so no namespace was
  violated" would make the allowlist decorative — the one request it must stop is
  the one that asks for everything at once.

The second rule also catches genuinely cluster-scoped resources: `nodes`,
`persistentvolumes`, `storageclasses`, `namespaces` itself. That is correct — a
grant confined to namespaces has not been given the cluster. An operator who
wants those adds them to `resources` and drops the namespace list, or issues a
second, cluster-scoped grant.

### The deployment floor and the grant intersect

`executors.kube_guard.verbs` / `.namespaces` / `.resources` are a **hub-wide
floor**, not the policy a session runs under. Each grant carries its own, and the
session gets `floor.Intersect(grant)`:

- an operator who sets the floor to read-only has made every grant on the hub
  read-only, regardless of what any grant asks for;
- a grant that asks for less than the floor allows still gets only what it asked
  for;
- an operator who leaves the floor empty lets each grant speak for itself — and
  a grant that says nothing still gets read-only, because that is the default at
  the grant level too.

Verbs intersect exactly; there are eight of them and set intersection is the
whole answer. The glob lists cannot, because there is no general way to compute
the intersection of two glob languages. **The narrowing is conservative
instead**: an entry from the grant survives only if the floor already admits it
as a literal string. A floor of `team-*` over a grant for `team-a` narrows
correctly, because the floor's pattern matches the grant's string. A floor of
`app-1` over a grant for `app-*` keeps nothing, even though `app-1` is in both.

**Every dimension fails closed.** An empty intersection on any of them refuses
the lease rather than producing a session, and the error names both sides:

```
grant grant_187bd2… cannot be honoured under this hub's kube_guard policy
(read-only ns=team-a): policy permits no verbs

grant grant_9c41af… cannot be honoured under this hub's kube_guard policy
(read-only ns=team-a): namespaces: the grant asks for team-b but this hub's
policy floor allows only team-a, and no entry of the first is covered by the
second; widen the floor or narrow the grant to a literal subset of it
```

The glob dimensions have to refuse rather than return the empty list, and the
reason is worth being explicit about, because the obvious implementation is a
fail-*open*. An empty `Namespaces` list does not mean "no namespaces" — it means
"no namespace confinement". Returning one from the narrowing function would take
two policies, neither of which allowed reading `kube-system`, and produce a
session that could read every namespace in the cluster. A widening, emitted by
the narrowing function, in the one direction a security control must never fail.
So `Intersect` returns an error and `GuardKubeconfig` turns it into a failed
lease.

In practice this rarely fires: the common floor is empty or `*`, where no
narrowing happens at all. An operator who does write one should **write the
floor as a literal superset of every grant** — a floor whose patterns match
every namespace string any grant names narrows correctly, and a mismatch is a
loud refusal at lease time rather than a quiet hole.

---

## Creating a read-only grant, end to end

Nothing about the grant workflow changes when the monitor is on. The same two
commands produce a stronger delivery.

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

That grant is **read-only**: `--verbs` was not given, and an unset verb list
means `get`, `list`, `watch`. Nothing in the summary says "verbs", because the
summary prints the constraint as written and the constraint is empty — the
read-only reading is what the absence means.

To say it out loud, or to ask for more:

```console
# explicit read-only — identical behaviour, visible in the grant summary
$ cloop secret grant prod-kube --to project:/srv/app --contexts prod \
    --namespaces team-a --verbs get,list,watch --ttl 12h

# a project that deploys: reads, plus the writes a rollout needs
$ cloop secret grant prod-kube --to project:/srv/app --contexts prod \
    --namespaces team-a --verbs get,list,watch,create,update,patch --ttl 2h
```

The verbs are RBAC's, spelled the way RBAC spells them, so a list can be copied
out of a `Role` that already exists: `get`, `list`, `watch`, `create`, `update`,
`patch`, `delete`, `deletecollection`. A misspelling is refused when it is
written, not discovered inside somebody else's run.

A kubeconfig grant still needs `--namespaces` and/or `--contexts` — there is no
implicit wildcard, and `--verbs` does not substitute for them. The two answer
different questions: the namespace list is *which parts of the cluster*, the verb
list is *what may be done to them*.

Confirm what will actually be delivered without materialising anything:

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

**`via monitor` is the line to look for.** Without the monitor the same grant
reads `kubeconfig read-only contexts: prod/team-a` and delivers the cluster
credential — same constraints, same TTL, materially different thing. The context
summary is deliberately taken from the *minimised* document rather than the
delivered one: under the monitor the delivered kubeconfig names one synthetic
context called `cloop`, and a row saying "contexts: cloop" would describe the
plumbing instead of the access.

---

## Turning it on

One section in the hub's `.cloop/config.yaml`:

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

`cloop hub bootstrap` writes this section with `tls: auto`, beside the git
proxy's, at `--external-url`'s host (Task 20409). With the Helm chart it is
`executor.kubeGuard.enabled=true` beside a certificate source from
`executor.monitorTLS` — `auto`, or a Secret: the chart advertises the monitor
at the hub's Service name, adds the port to the Pod and the Service, and, for a
Secret, points `ca_file` at the CA it generated or was given — see
[deploy/README.md](../../deploy/README.md#the-git-proxy-and-the-kubernetes-access-monitor).

Resource patterns name the resource, never a subresource: `pods` already admits
`pods/log`, and a pattern written as `pods/log` matches nothing at all, because
the string a pattern is matched against is `resource` for the core group and
`group/resource` otherwise.

- **Off by default.** Interposing a monitor changes the server a sandbox's
  `kubectl` talks to, so it is an operator's decision rather than something a
  config file acquires on upgrade.
- **TLS is required.** The session token rides an `Authorization` header on
  every request, and cleartext would publish it rather than deliver it. An
  enabled section with neither `tls: auto` nor both of `cert_file` and
  `key_file` is switched **off** at load rather than serving tokens in the
  clear — never read as `tls: auto`, which is an explicit choice.
- **`tls: auto` issues the certificate from the hub's own CA** — the one the
  [git proxy's](git-proxy.md) comes from, minted once per control plane,
  sealed under `CLOOP_SECRET_KEY` and replaced online with
  [`cloop hub ca rotate`](../operations/runbook.md#rotating-the-hub-ca) — as a 72-hour leaf for the host of
  `advertise_url` (and of a specific `listen_addr`), renewed by the cluster
  leader with two days to spare. The CA is what every kubeconfig the monitor
  issues carries as `certificate-authority-data` — both CAs, while one is being
  rotated, so a kubeconfig minted after the stage keeps working across the
  activation, and the run it was minted for records which. Needs `CLOOP_SECRET_KEY`;
  excludes `cert_file`, `key_file` and `ca_file`.
- **`ca_file` is the one place this is easier to deploy than the git proxy**
  with an operator's pair. A kubeconfig can carry its own trust anchor, so the
  PEM is embedded into the delivered document as `certificate-authority-data`
  and a self-signed hub certificate needs no change to the sandbox image. Empty
  falls back to `cert_file`, which is the right answer for a self-signed
  certificate and harmless for a publicly-signed one.
- **`advertise_url` must be reachable from where `kubectl` runs**, which is
  frequently not where the hub sees itself: a Kubernetes Service name for the Pod
  backend, `host.docker.internal` / `host.containers.internal` for a
  containerised agent, the hub's address on the link for an edge device. It
  becomes the `server:` field of a kubeconfig, so it must be a bare `https://`
  base — a path, query or fragment here produces requests nothing serves. Empty
  falls back to the bound address, which is correct only when the sandbox shares
  the hub's network namespace.
- **A session lasts `session_minutes` from dispatch, not for the run.** Default
  60, ceiling 720 — twelve hours, because a session that outlives a working day
  is indistinguishable from having handed the sandbox the kubeconfig outright. An
  out-of-range value is refused when it is written (`cloop config set`, `cloop
  config validate`) and reset to the default with a warning if it reaches `Load`
  by some other route; the monitor itself refuses a TTL above the ceiling rather
  than quietly halving one, because an operator who configured a day and silently
  got twelve hours would discover the difference as a `kubectl` that stopped
  working halfway through a long run. A run that outlives its session fails its
  next API call, with a message that says so.

Validation is not deferred to start time. `verbs`, `namespaces` and `resources`
are put through the same `Normalize()` and `Validate()` the monitor enforces
with, so a verb nobody spells correctly, a malformed glob, or a pattern carrying
`..` is refused when it is written rather than read as a working allowlist that
denies everything. A rejected policy resets **all three together** rather than
dropping the bad entry, because a half-applied policy is one nobody wrote and the
built-in default is narrower than any override an operator was reaching for. The
same holds for `session_minutes`, `min_tls_version`, `listen_addr` and
`advertise_url`; the repairs that could only produce an unusable or unsafe
monitor switch `enabled` **off**.

A hub that started the monitor says so, once:

```
ui: kubernetes access monitor on 0.0.0.0:8444, advertised as https://hub.internal:8444; policy floor read-only ns=team-*
```

A hub that could not start it comes up anyway, and says exactly what is not in
effect:

```
ui: kubernetes access monitor NOT started: kubernetes monitor listen on 0.0.0.0:8444: bind: address already in use
    executors.kube_guard is enabled, so no kubeconfig grant can be
    delivered: leases needing one will be refused rather than handed the
    cluster credential directly. Fix the section or set enabled: false.
```

### Checking it from the outside

[`cloop hub doctor`](../operations/runbook.md#configuration-health-cloop-hub-doctor)
reports on the monitor under the `kubeguard.*` checks, and it is worth running even when
nothing appears to be wrong — because when this is misconfigured, nothing does
appear to be wrong. A hub with the monitor off leases, dispatches and runs
`kubectl` exactly like one with it on.

| Check | What it catches |
| --- | --- |
| `kubeguard.enabled` | The monitor is off while Kubernetes access is configured. **Fails** while an active kubeconfig grant claims namespaces or verbs and nobody acknowledged delivering it without the monitor — it is refused at every dispatch (Task 20420) — naming each grant; **warns** while acknowledged ones are delivered unenforced, naming who acknowledged each and why, and while grants claiming nothing are delivered with the cluster credential. A pass states the policy and session length actually in force. |
| `kubeguard.tls` | `cert_file`, `key_file` or `ca_file` missing or unreadable — the monitor will not start and every kubeconfig lease will be refused. Under `tls: auto`: no `CLOOP_SECRET_KEY` (the monitor will not start), or a leaf that does not chain to the hub CA, has less than a day left — the leader renews with two — or does not name the host of `advertise_url`. Passes before the hub has first started, when there is nothing issued yet. |
| `kubeguard.advertise_url` | Unset, or loopback, so `kubectl` inside a Pod or an edge device cannot connect. This is the most common misconfiguration, because the wrong value works perfectly on the machine it was written on. |
| `kubeguard.advertise_reachable` | Nothing is listening at the advertised address. Reported, never failed: the hub is not on the sandbox's network, so a Service name that does not resolve here is frequently correct. |
| `kubeguard.verbs` | The deployment floor permits writing, so a grant on this hub may be given authority to change a cluster. |

Two things are true at once there, and the split is deliberate. The **dashboard
still boots** — `cloop ui` is also how a single-project install runs. But
**kubeconfig leases stop**: a hub told to intercept does not quietly go back to
delivering the cluster credential, because a security control that disappears
when it fails to load is one nobody can rely on. Everything that is not a
kubeconfig grant is unaffected.

A milder line, `ui: kubernetes monitor decisions will go to stderr, not the audit
trail: …`, means the boundary still holds and the evidence just is not in the
database.

### Proven on a cluster

Until Task 20385 nothing put the monitor in front of a real API server: its
tests used a fake one on loopback, and the device kit's stub read the kubeconfig
with `sed` and spoke `curl`. [`tests/kube`](../../tests/kube/README.md) now does,
on every CI run, against the hub the Helm chart installs on kind with
`executor.kubeGuard` on and `auditAllowed` set — on one replica, and again on a
hub cluster of three, where the Pod's requests reach members that did not mint
its session and are forwarded:

- a kubeconfig for a ServiceAccount that may **edit** a test namespace is stored
  as a secret and granted to a project for that namespace with no verbs — so a
  refused write can only have been refused by the monitor;
- the task's Pod receives a kubeconfig whose `server:` is the monitor's Service
  URL and whose CA is the chart's, and the real `kubectl` in it runs
  `kubectl get pods` — discovery and the list, forwarded with the cluster
  credential — and `kubectl create configmap`, refused as read-only before the
  API server sees it (`K0`–`K2`);
- the same kubeconfig is granted a second time, for a second namespace the
  ServiceAccount may also edit, with `create` (Task 20413): the Pod receives one
  kubeconfig with a context for each grant, `current-context` the read-only one,
  and `kubectl --context` reaches each grant's own namespace through the monitor
  and is refused in the other's and in `kube-system` — the cluster credential
  could read both, so only the monitor stood between — while the second
  context's `create configmap` lands in its namespace (`K4`);
- the trail holds a `kubeguard.request_allowed` row for the list and a
  `kubeguard.request_denied` row for the create, both naming the run's project,
  and the second grant's write allowed in its namespace;
- no configmap was created, and the cluster credential reached no part of the
  Pod;
- and the project the Pod runs is not in the repository at all: `acme/granted`
  holds no `.cloop/`, the goal and the task exist only on the hub, and they reach
  the Pod as the project seed in its lease Secret. Afterwards the hub's own plan
  shows the task done — the run's outcome came back as a frame at the end of the
  Pod's log — and a second Start does not run it again (Task 20402; see
  [the seed in a Secret, the outcome in the log](executors.md#kubernetes-the-seed-in-a-secret-the-outcome-in-the-log-task-20402)).

What it does not cover: watches and the subresource refusals (`exec`, `attach`,
`portforward`, `proxy`), which unit tests pin against the fake API server; a
delivered kubeconfig's namespace default, which the run names explicitly with
`-n`; and a Pod's direct route to the API server, which only a CNI that enforces
NetworkPolicy closes — CI's kind cluster does not, as the hub's probe reports on
every run.

### Where it runs, and why there is no `cloop kube-guard`

The monitor is a background service of the hub process, started from
`bootstrapExecutors` (`pkg/ui/kubeguard.go`) alongside the git proxy. There is no
standalone command, and that is a property of the design rather than an omission.

Sessions live in a `kubeguard.Registry`, which is memory, and they hold the
cluster credential. **The process that mints must be the process that serves.** A
separate `cloop kube-guard` would authenticate against an empty registry and
refuse every request the hub had authorised. The alternative that would make one
work is a shared session store holding what a session spends, which means a
kubeconfig at rest in a second place for a topology nobody has asked for. The
session *record* (Task 20383) holds none of that, and is for a different job:
bringing a session back in the process that adopts its run.

It follows that the monitor is a process-wide singleton and must start before any
executor registers, for the same reason the git proxy does: a broker constructed
before the monitor existed would route nothing.

### A hub restarted mid-run

A device keeps running its task while its hub restarts. Since Task 20382 the
process that adopts the run takes its lease over; since Task 20383 it restores the
monitor sessions that lease fed, so the workload's next `kubectl` call is served
with the bearer token it already holds.

A hub stopped gracefully suspends a recorded session — it stops serving it,
writes no close row, and leaves the record open; a SIGKILL leaves the same. When
the device's agent reconnects and the run is adopted, each open session the
run's lease feeds is retired if it lapsed meanwhile, taken over by a conditional
write on its holder (of two processes adopting the run, one gets it), and
restored under its id and token hash with:

- **its cluster credential re-derived from the grant** — the grant's kubeconfig,
  minimised exactly as the monitor was given it at mint, refused if it no longer
  names the cluster the session was pinned to;
- **its policy narrowed, never widened** — the deployment floor intersected with
  the grant as a fresh mint would compute it, intersected again with what the
  session was given;
- **its deadline held to this hub's session TTL** from when it was issued, and a
  record no mint could have written — a deadline beyond the 12-hour ceiling, no
  issue time — refused.

A [`kubeguard.session_restored`](../reference/audit-events.md#kubeguard) row names
the process that held it. A grant revoked or expired while no process held the
lease refuses the lease, and its sessions are closed with the reason and the
device scrubbed. A request made before the run was adopted, presenting a session
whose holder stopped, waits up to 60 seconds for the restore instead of failing —
kubectl's discovery burst shares one wait — see [the git
proxy's](git-proxy.md#a-hub-restarted-mid-run) account of why it is not restored
on demand, and gets a 401 if nothing restores it. A restore that failed for a
reason that may pass is retried on the lease's keepalive and by the next request,
unless another process has taken the session or the lease over since. The
leader's janitor retires the records of sessions that closed or lapsed.

---

## Kubernetes shares: a cluster behind a credential plugin

The clusters enterprises run sign people in through an **exec credential
plugin** — `kubelogin` on AKS with Entra ID, `aws eks get-token` on EKS,
`gke-gcloud-auth-plugin` on GKE — and the hub refuses such a kubeconfig, rightly:
running the plugin would execute a program named in an uploaded file on the
control-plane host. Until Task 20416 the refusal was the end of it. The
developer had to create a ServiceAccount, choose and bind roles, mint a token
and assemble a kubeconfig by hand, and the token then expired mid-run, because
managed API servers cap how long a TokenRequest token may live.

`cloop remote kube share` does that work from the developer's own terminal, and
the hub keeps the result working:

```console
$ cloop login https://cloop.example.com
$ cloop remote kube share aks-dev --context aks-dev --namespaces payments,payments-staging
```

### What runs where

| Step | Where | With what |
| --- | --- | --- |
| Run the exec plugin | the developer's machine | `pkg/kubeexec`: client.authentication.k8s.io `v1` and `v1beta1` ExecCredential, `interactiveMode` (`Never`, `IfAvailable`, `Always`), `provideClusterInfo` with the cluster's `client.authentication.k8s.io/exec` extension, the plugin's own stderr for its device-code prompt, its stdout read under a 1 MiB cap and never echoed into an error |
| Create the ServiceAccount and its bindings, mint the token | the cluster, as the developer | the credential the plugin printed |
| Store the share | the hub, as the developer | `POST /api/secrets` over the `cloop login` session — a personal secret, as the dashboard would store it |
| Renew the token | the hub | the share's own token, through its self-renewal Role — when the hub runs this monitor |
| Revoke | the hub's authorisation, the cluster, then the hub | `GET /api/secrets/{id}/authorize`, the developer's credential again, then `DELETE /api/secrets/{id}` |

The hub never runs the plugin, and the guarantee is structural: only `cmd`
imports `pkg/kubeexec`, so no package the hub, the monitor, the broker or an
executor runs can reach it by any path
(`TestOnlyTheTerminalImportsTheCredentialPluginRunner`). The kubeconfig the hub
stores is static — server, CA, one bearer token — and passes the same
`ParseKubeconfig` every other kubeconfig does. The dashboard refuses an
exec-plugin kubeconfig at upload, naming the plugin and giving the
`cloop remote kube share` command with the hub's URL, the chosen name and the
document's context and namespace filled in.

### What a share creates

| Object | Scope |
| --- | --- |
| ServiceAccount `cloop-<name>-<id>`, `automountServiceAccountToken: false` | in `--sa-namespace` (read access: the first shared namespace by default) |
| RoleBinding to ClusterRole `view` — `edit` with `--access write` | in each of `--namespaces`; a ClusterRoleBinding only with `--cluster-wide`, and only for read |
| Role `…-renew`: `create` on `serviceaccounts/token`, `resourceNames: [the ServiceAccount]`, and its RoleBinding | in the ServiceAccount's namespace, and only when the hub renews the share |

Every object carries `cloop.dev/kube-share=<id>` and
`app.kubernetes.io/managed-by=cloop`, plus annotations naming the share, the
hub, the owner and the access. The owner annotation is the hub's own key for the
person sharing — a lowercased email, or `sub:` and the subject — which the
terminal reads from `/api/me`'s `identity`. The label deliberately shares nothing
with the `kubernetes` executor's own (`cloop.dev/managed`), so the executor's
orphan sweep can never take a share for something it owns.

The secret's metadata records the share (`kube.share`, `kube.namespaces`,
`kube.access`, `kube.renewal`, `kube.context`). Everything a revoke or a renewal
acts on is the hub's to write, never the client's (Task 20420), because the
metadata is its uploader's and a revoke or renewal runs with somebody else's
credentials — often an administrator's:

| Key | Written from |
| --- | --- |
| `kube.service_account` | the token's claims, which must name the share's own ServiceAccount — `cloop-<name>-<id>`, in a valid namespace, or the upload is refused |
| `kube.issued_at`, `kube.expires_at` | the token's claims |
| `kube.server`, `kube.ca_sha256` | the stored kubeconfig: its server, and the SHA-256 of the CA it trusts (`none` when it names none) |
| `kube.owner` | the authenticated uploader |
| `kube.objects` | what the share's plan creates, from the fields above — never the client's list |

The token's claims are not verified at upload — the hub cannot, short of asking
the cluster with them — which is why they are held to the share's own
ServiceAccount, and why revoke and renew [check the cluster's own
objects](#what-revoke-and-renew-trust) besides.

**Write access needs a ServiceAccount namespace it cannot write.** `edit` is
not "write most objects": it may create Pods and Secrets, impersonate
ServiceAccounts and create tokens for them, in its namespace. A ServiceAccount
that can write where it lives can therefore hand a workload its own credential
— a Pod running as it whose logs print its token, a Secret of type
`kubernetes.io/service-account-token` — through requests the monitor reads as
ordinary writes, producing a credential that bypasses the monitor and outlives
the share's TTL. So `--access write` requires `--sa-namespace` outside
`--namespaces`, and cluster-wide write is refused: there is no namespace
outside it. `view` reads neither Secrets nor the logs of a Pod it could have
started, so a read share may live where it reads.

### Renewal through the monitor

When the hub runs this monitor (`executors.kube_guard.enabled`, which
`GET /api/secrets` reports as `kube_guard`), a share defaults to **renewal by
the hub**:

1. **One member renews.** A leader duty finds every hub-renewed share past half
   its token's life — a 24-hour token at 12 hours, a 10-minute one at 5 — and
   mints the next token with a TokenRequest authenticated by the token the share
   holds, for the same lifetime. The self-renewal Role permits exactly that and
   nothing else. The new kubeconfig differs from the old in the token alone
   (`kubeshare.ReplaceToken`) and is sealed in place under the secret's own id,
   so every grant keeps pointing at it (`Broker.RenewSecret`). Each renewal is a
   `secret.renew` row by `hub` naming both expiries.
2. **Every member updates its sessions.** A monitor session holds the cluster
   credential it was minted from, and a run's session can outlive the token
   behind it. Once a minute each member re-derives, for every live session
   standing on a renewed share, the minimised kubeconfig from the lease's grant
   — the way a [restored session](#a-hub-restarted-mid-run) is re-derived — and
   `Registry.UpdateUpstream` swaps it in, refusing anything but a changed bearer
   token: the server the session is pinned to, its CA, TLS name, proxy and client
   certificate must be unchanged. The session's connection pool stays; the next
   request presents the new token. A run dispatched before the renewal keeps
   working after the token it started with has expired.
3. **The monitor keeps the permission the hub's.** `serviceaccounts/token` is
   [refused for every verb](#subresources-that-are-not-data), so a sandbox under
   a write grant — even one whose namespaces include the ServiceAccount's own —
   cannot mint itself a token, though the cluster's RBAC would let the
   ServiceAccount do it (`TestTheMonitorNeverForwardsATokenRequest`).
4. **A self-renewing share is delivered through the monitor or not at all.** As a
   file in a sandbox it would be a credential that can extend itself. A hub whose
   monitor is turned off later refuses its grants at dispatch, with that said on
   the project's Activity tab, and keeps renewing it for when the monitor is back.

A share is its owner's credential, and the hub renewing it keeps it alive. So a
personal share whose owner the hub **denies** — a global deny role binding on
their email or subject, which an offboarding and a suspension at the identity
provider (SCIM) write, or a provisioned user the provider deactivated, since a
suspension that resolved neither denies only a username or oid claim — is **not
renewed** (Task 20420), whether the person was suspended or offboarded with the
secret kept under a legal hold. The share says why (`kube.renew_state:
stopped`, `kube.renew_error` naming the suspension, the hold's date and matter,
or the binding's reason; `cloop remote kube list` shows "stopped by the hub"),
and the refusal is a `secret.renew` deny row, once per distinct reason. A token
pushed from a terminal does not keep it alive either: `cloop remote kube renew`
is told so before it mints anything, and the hub refuses the push (409). The
check runs every pass, so a reactivated owner's share resumes; a token that
expired meanwhile is lapsed. A shared share belongs to the organisation and is
renewed whatever happens to the person who made it, as an offboarding keeps it.

A renewal that fails records why on the share (`kube.renew_error`, shown by
`cloop remote kube list`) and is audited once per distinct cause, not once a
minute. One that finds the token already expired — the hub was down for more
than half its life — or that the cluster no longer accepts it (the ServiceAccount
deleted) marks the share **lapsed**: nothing the hub holds can authenticate the
next TokenRequest any more, and the duty leaves it alone. Its owner revives it
with `cloop remote kube renew`, which mints the next token with their own
credentials.

### Without the monitor

A hub that does not run the monitor would hand the share's token to the sandbox
as a file, and with it the self-renewal permission — so none is installed
(`--renewal manual`; a developer may ask for it on any hub). The developer renews
from the terminal: `cloop remote kube renew` mints a token with their own
credentials and posts it to `POST /api/secrets/{id}/renew` together with where it
was minted, and the hub stores it only after the cluster has authenticated it as
the share's own ServiceAccount (a SelfSubjectReview; on a cluster too old to
answer one, the token's claims are checked alone and the response says so). A run
already holding the old kubeconfig keeps it until that token expires; the next
dispatch gets the new one. Without the monitor, a grant of the share is itself
[refused unless acknowledged](#without-the-monitor-refused-unless-acknowledged),
like any kubeconfig grant that names namespaces or verbs.

### What revoke and renew trust

`cloop remote kube revoke` and `renew` act on the cluster with the developer's
own credentials — the colleague or administrator running them — over a share
whose metadata its uploader wrote, and which names the context they default to.
Before Task 20420 a `secret.grant` holder could therefore upload a share listing
`ClusterRoleBinding/cluster-admin` among its objects and have an administrator's
revoke delete it, or name `kube-system`'s ServiceAccount and a server of their
own and have a colleague's renew mint a token for it and hand it to the hub,
which then sent it to that server to check. Now:

1. **The hub decides first.** Both ask `GET /api/secrets/{id}/authorize?action=delete|renew`
   before anything touches the cluster — the predicates the `DELETE` and the
   renewal apply — and stop, having touched nothing, when the hub refuses. (A hub
   too old to answer refuses too; `revoke --force` then deletes only the hub's
   secret.)
2. **The context must reach the share's cluster.** The local context's API
   server must be the share's `kube.server`, and the CA it trusts must hash to
   `kube.ca_sha256`; otherwise both refuse, naming `--context`, rather than act
   with the developer's credentials on another cluster. A share made with
   `--server` (the hub reaches the cluster at another address) is renewed and
   revoked through a context for that address.
3. **Revoke deletes only what the share created.** The candidates are what its
   plan creates, what its metadata lists and what carries its label in its
   namespaces; each is **read back from the cluster** and deleted only if it
   carries `cloop.dev/kube-share=<id>` **and** a `cloop.dev/owner` annotation
   naming the share's owner (the hub's record, or for a personal share its
   owner), by uid and resourceVersion so an object changed after it was read is
   not the one deleted. Anything else is reported — "Not deleted, not this
   share's" — and left alone; a name that is not one a share could create never
   becomes a request at all. A ServiceAccount that exists and is not the share's
   fails the revoke: the share's tokens stay valid until they expire.
4. **Renew mints only for the share's own ServiceAccount.** It must be named as a
   share names it, and read back from the cluster with the share's label and
   owner, or renew refuses before minting.
5. **A token goes only to the server that minted it.** The terminal posts the
   server and CA it minted at; the hub refuses — sending the token nowhere —
   unless they are the stored kubeconfig's, and only then asks that server to
   confirm it.

### Revoking

`cloop remote kube revoke` asks the hub, then deletes the ServiceAccount
**first**, which invalidates every token ever minted for it at once — the hub's,
a live session's, any copy — then its RoleBindings and Role, then sweeps the
share's namespaces for anything else carrying its label (each checked as above),
and only then deletes the hub's secret, which revokes its grants and closes the
monitor sessions standing on them. A revoke the cluster cannot complete keeps the
secret so it can run again; `--force` deletes it anyway and names what is left of
the share's own — or, when the cluster was not touched, lists the candidates with
their owner annotation to check before deleting. It never advises a delete by
label: anybody who may label objects could give theirs the share's id.

### Proven on a cluster

`TestKubeShareWithAnExecPlugin` in [`tests/kube`](../../tests/kube/share_test.go)
runs on a kind cluster in CI: a developer ServiceAccount holding `admin` in three
namespaces, a kubeconfig that signs in only through a fake exec plugin
(`v1`, relative command, `provideClusterInfo`), a hub with the monitor on and the
host executor. It shares with `--access write --ttl 10m` — the shortest token the
API issues — checks the objects and that RBAC alone *would* let the
ServiceAccount mint its own token, then dispatches a run whose probe reads and
writes through the monitor and is refused the ServiceAccount's own token, a raw
TokenRequest for another and `kube-system` — and, under that write grant, a
ServiceAccount token Secret, a Pod and a Deployment as another ServiceAccount, a
`hostPath` Pod, a new image for a Deployment already running as another
ServiceAccount and a RoleBinding, none of which exists afterwards, while a Pod as
the default ServiceAccount passes (Task 20420). It waits for the hub's renewal and
for the first token to expire, has the same run read and write again, revokes,
finds no labelled object anywhere, and has the run confirm it is cut off. Then it
uploads a crafted share — a token for a ServiceAccount the administrator made, an
object named like the share's and a decoy labelled with its id by another owner,
metadata listing `cluster-admin`'s binding — and revokes it with a cluster-admin
kubeconfig: nothing is deleted, the hub's secret is kept, and `--force` deletes
only that. About thirteen minutes, most of it waiting out the first token.

---

## What it enforces, and what it does not

**Enforced, outside the sandbox, on every request:**

| | |
| --- | --- |
| Verb allowlist | `create`, `update`, `patch`, `delete`, `deletecollection` are refused under the default. |
| Namespace allowlist | Both directions: a named namespace outside the list, and a request that names none while a list exists. |
| Resource allowlist | When set, matched as RBAC spells it. |
| Non-resource URLs | Readable only, and only inside the allowlist; discovery by default. |
| Dangerous subresources | `exec`, `attach`, `portforward`, `proxy`, `ephemeralcontainers`, and the TokenRequest API `serviceaccounts/token` — refused for every verb, not configurable. |
| Credentials minted by a write | A ServiceAccount token Secret, a workload running as a non-default ServiceAccount or reaching the node, a patch to one already doing either, RBAC writes and CertificateSigningRequests — refused under every grant; a body the monitor cannot read is refused for these kinds. See [writes that would mint a credential](#writes-that-would-mint-a-credential). |
| Protocol upgrades | Refused. SPDY and websocket both. |
| Impersonation | `Impersonate-*` stripped, never forwarded. |
| Request body size | Bounded at 3 MiB by default, and **refused rather than truncated**: a declared `Content-Length` over the cap is rejected before a byte is read, and a chunked body that runs over is cut with `body_too_large`. Truncating was worse than either — the API server answered with its own parse error, so the sandbox was told its JSON was malformed when its request was simply too large. Under the default read-only policy no request has a body at all. |
| Session lifetime | TTL-bounded, and revoked when the lease is released. |

**Not enforced, and worth saying plainly:**

- **The cluster's RBAC is still the ceiling.** The monitor can only narrow. If
  the granted credential cannot read `secrets` in `team-a`, a policy that permits
  it does not make it work — the API server's own 403 is forwarded back.
- **Response content is not filtered.** A permitted `get secrets` in a permitted
  namespace returns the secret — including a ServiceAccount token Secret
  somebody else created there before, which `edit` may read. The monitor decides
  *which requests*, not *what comes back*; narrowing that is what `resources` and
  the namespace list are for.
- **The credential-minting checks know the shapes they name.** A custom resource
  that names a ServiceAccount under some key other than `serviceAccountName` or
  `serviceAccount`, an admission webhook that rewrites Pods (cluster-scoped, so
  refused under a namespace list, but not under a grant without one), and a
  container that escalates by capabilities rather than `privileged` are not
  recognised: enforce at least the `baseline` Pod Security Standard on namespaces
  you grant writes in. A patch is checked against the object as it was read a
  moment before; a concurrent change by someone else between the read and the
  patch is not.
- **Cluster-scoped reads are refused, not scoped.** With a namespace allowlist in
  force there is no way to allow `get nodes` — it is refused as
  `cluster_scope`. Use a second grant without a namespace list, resource-limited
  instead.
- **The glob intersection is conservative, so a floor can refuse a grant it
  logically overlaps.** A floor of `app-1` against a grant for `app-*` shares
  `app-1`, but glob languages cannot be intersected in general, so the lease is
  refused rather than guessed at. This fails closed — it costs an operator a
  loud error, not a hole. See
  [the floor](#the-deployment-floor-and-the-grant-intersect).
- **It does not bind a sandbox that reaches the cluster some other way.** The
  monitor governs the credential cloop delivers. A sandbox with direct network
  reach to an API server still has no credential for it — but if a cluster grants
  `system:anonymous` something useful, that path is a network question, not a
  policy one. Pair the monitor with
  [egress filtering](../reference/configuration.md#ip-layer-egress-filtering).
- **It does not govern the hub's own cluster credential.** The `kubernetes`
  executor leases a kubeconfig to *create Pods*, through a broker of its own that
  is not routed through the monitor. That credential is the hub acting as itself,
  never delivered into a sandbox, and interposing a read-only monitor in front of
  it would stop the hub scheduling work. See
  [the `kubernetes` backend](executors.md#kubernetes--kind-kubernetes-isolation-remote).
- **A compromised hub is a compromised credential store.** Nothing here defends
  against that. What it buys over the status quo is that there is now exactly one
  such store to protect instead of one per running sandbox — and a second
  listener on the hub, reachable by everything the sandbox network can reach, so
  bind `listen_addr` as narrowly as that network allows.

---

## Audit events and metrics

`Registry.OnEvent` receives every decision. Events carry identifiers, resource
names, namespaces and reasons — there is no field on `kubeguard.Event` that could
hold credential material or object content, which is what makes the table safe to
export to a SIEM.

| Kind | Emitted when | Notes |
| --- | --- | --- |
| `request_denied` | policy refused a request | **The row that matters.** The only place a sandbox's attempt to write to, or read outside, its granted scope — or to mint itself a credential — is written down. Nothing else in cloop would record it. Alert on it. |
| `request_allowed` | a request was forwarded | **Off** by default: a `kubectl get pods` is several requests and a watch is one that never ends, so a row per allowed request would bury the denials in discovery traffic. `executors.kube_guard.audit_allowed: true` turns it on (Task 20385), for a hub whose trail has to say what a sandbox *read*. |
| `session_minted` | a session was created | `Detail` carries the policy summary and the expiry. |
| `session_closed` | a session was revoked, released or reaped | `Detail` carries the reason and the allowed/denied counters. Also written for a session that ended while no hub process served it — not restored with its run, or retired once it lapsed. |
| `session_restored` | the hub process that adopted a run restored its session (Task 20383) | `Detail` names the process that held it until then. |
| `rejected` | refused *before* a session was identified, or a hub-side failure | No credential, an unknown token, an expired or revoked session, an unreachable cluster. Distinct from `request_denied`: nothing here got as far as a policy decision. |

`OnEvent` runs on the request goroutine, so a slow sink delays a sandbox's API
call. The hub's own sink does a single insert for that reason.

They land in the same hash-chained `audit_events` table as the credential broker,
with `entity_type` `kubeguard`, the session id as the entity, and the kind
prefixed: `kubeguard.request_denied`, `kubeguard.request_allowed`,
`kubeguard.session_minted`, `kubeguard.session_closed`,
`kubeguard.session_restored`, `kubeguard.rejected`.

```console
$ cloop audit-log list --entity kubeguard --since 7d
$ cloop audit-log list --type kubeguard.request_denied --since 30d --json
```

The payload carries the session, the cluster URL, the context, the verb, the
resource, the namespace, the object name, the deny reason, the project, task,
executor, grant and lease ids, and the prose detail — and nothing else. An audit
write that fails does not fail the request, but the decision has to be visible
somewhere, so it goes to stderr instead, prefixed `kube-guard:`.

A `request_denied` is not a false positive to be tuned away. A task doing what it
was asked to do never produces one, so every occurrence is either a workload
doing something it was not granted or a policy narrower than the task it was
minted for. Both are worth a human.

### Metrics

Two counters, exported at `/metrics` — see [metrics](../operations/metrics.md).

| Metric | Type | Labels |
| --- | --- | --- |
| `cloop_kubeguard_requests_total` | counter | `result` — `allowed` or `denied` |
| `cloop_kubeguard_denials_total` | counter | `reason` |

`reason` is one of `verb_not_allowed`, `namespace_not_allowed`, `cluster_scope`,
`resource_not_allowed`, `dangerous_subresource`, `non_resource_path`,
`protocol_upgrade`, `body_too_large` and `unauthenticated` — and, for a write
that would [mint a credential](#writes-that-would-mint-a-credential) (Task 20420),
`service_account_token_secret`, `workload_service_account`, `host_access`,
`rbac_binding`, `rbac_role`, `certificate_signing_request` and
`unreadable_body`. The same reason is on the `request_denied` audit row.

A proxy-side failure — an unreachable cluster, an unusable credential — is
counted as **neither** allowed nor denied. Conflating a broken upstream with a
policy refusal would make the denial metric lie in exactly the situation an
operator is paging on.

**A workload expecting write access it was not granted:**

```promql
rate(cloop_kubeguard_denials_total{reason="verb_not_allowed"}[5m]) > 0.1
```

**Someone trying to get a shell in a pod** — this one should be flat at zero:

```promql
rate(cloop_kubeguard_denials_total{reason="dangerous_subresource"}[5m]) > 0
```

**A workload reaching for a credential of its own** — also flat at zero:

```promql
sum(rate(cloop_kubeguard_denials_total{reason=~"service_account_token_secret|workload_service_account|host_access|rbac_binding|rbac_role|certificate_signing_request"}[5m])) > 0
```

---

## Troubleshooting

**`Unable to connect to the server: x509: certificate signed by unknown
authority`** — the delivered kubeconfig's `certificate-authority-data` does not
match what the monitor presents. Set `ca_file` to the issuing CA's PEM; with it
empty the hub embeds `cert_file` itself, which is right for a self-signed
certificate but not for one signed by a private CA whose chain matters. Under
`tls: auto` the two cannot disagree; the matching failure there is
**`x509: certificate is valid for …, not …`** — the leaf does not name the host
the kubeconfig's `server:` points at. The hub issues a leaf for the
`advertise_url` it starts with, so restart it after changing that, and run
`cloop hub doctor` (`kubeguard.tls`).

**`Unable to connect to the server: dial tcp … connect: connection refused`** —
`advertise_url` names an address the sandbox cannot reach. The hub logged what it
advertises at startup; compare it with what the sandbox can actually resolve and
route to. This is the single most common deployment mistake, because everything
on the hub side works before it is discovered.

**`the server could not find the requested resource`, on every command** — a
custom `non_resource_paths` list that omits discovery. Remove the override and
let the default set apply, or include `/api`, `/api/*`, `/apis`, `/apis/*`,
`/apis/*/*` at minimum.

**`this session has read-only access to the cluster, so it may not create …`** —
working as configured. Either the grant names no `--verbs`, which means
read-only, or the intersection with the hub-wide floor left only read verbs.
Widen the grant, or the floor, deliberately.

**`pods without a namespace would read across the whole cluster; this session is
confined to team-a, so name one with -n`** — a `--all-namespaces` read, or a
cluster-scoped resource, under a namespace-confined grant. Pass `-n`, or issue a
second grant for the cluster-scoped part.

**`pods/exec is not readable through the cloop Kubernetes monitor`** — by design,
for every verb, and not configurable. A workload that genuinely needs to exec
needs a kubeconfig grant on a hub without the monitor in that path.

**`serviceaccounts/token is refused by the cloop Kubernetes monitor for every
verb, under every grant`** — `kubectl create token`, or anything else asking the
TokenRequest API for a credential, from a sandbox. By design: the token would
bypass the monitor from then on. A workload holds the access its grant gives it,
through the monitor, and no credential of its own.

**`kubeconfig grant constraints cannot be enforced without the Kubernetes access
monitor`** — a grant naming namespaces or fewer than every verb, on a hub with
`executors.kube_guard` off. [Turn the monitor
on](#turning-it-on) (`enabled: true`, `tls: auto`); or, where delivering the
credential unenforced is genuinely acceptable, have an administrator run
`cloop hub grant unguarded <grant-id> --reason <why>`. `cloop hub doctor` lists
every such grant.

**`… is refused by the cloop Kubernetes monitor: it names ServiceAccount …`**,
**`… it mentions "kubernetes.io/service-account-token" …`**, **`… it asks for a
hostPath volume …`**, **`… under every grant: a binding hands …`** — a write that
would give the workload a credential of its own; see [writes that would mint a
credential](#writes-that-would-mint-a-credential). Run the workload as the
namespace's default ServiceAccount, and create RBAC, named ServiceAccounts'
workloads and node-level workloads as a cluster administrator.

**`… the object already runs as ServiceAccount … and a patch keeps that`** — a
change to a workload somebody else created to run as its own ServiceAccount.
Change it as a cluster administrator.

**`… cannot read this one (it is sent as application/vnd.kubernetes.protobuf)`** —
a client configured for protobuf writes. Use JSON (`--kube-api-content-type
application/json`, or leave client-go's default).

**`kubeconfig … is a share the hub renews, so its ServiceAccount may create
tokens for itself, and it is delivered only through the Kubernetes access
monitor`** — a self-renewing [share](#kubernetes-shares-a-cluster-behind-a-credential-plugin)
granted on a hub that delivers kubeconfigs without the monitor. Turn the monitor
on, or share the cluster again with `--renewal manual`.

**`cloop remote kube revoke` or `renew`: `the context reaches …, and the share is
for …`** or **`the context trusts another CA`** — the context (by default the one
the share was made from, as its metadata names it) does not reach the share's
cluster. Pass `--context` naming one that does; for a share made with `--server`,
a context for the address the hub uses.

**`Not deleted, not this share's: …`** — revoke found an object it was asked
about, or one carrying the share's label, that the cluster does not show as the
share's own: no label, another share's, or an owner annotation that is not the
share's owner. It is left alone. If the share's ServiceAccount is among them the
revoke fails and keeps the hub's secret — the share's tokens are still valid;
look at who made the ServiceAccount before deleting anything.

**`cloop remote kube list` shows a share as `stopped by the hub`** — its owner is
denied on the hub: suspended at the identity provider, offboarded with the
secret kept under a legal hold, or a deny role binding. The line under the table
says which. Renewal resumes when the deny goes.

**`cloop remote kube list` shows a share as `hub, failing`** — read the
`the last renewal failed:` line under the table. `may not create its own token:
its self-renewal Role or RoleBinding (…-renew) is missing or was changed` means
somebody edited the Role; recreate the share, or renew it by hand. A share shown
**`lapsed`** expired before the hub could renew it — the hub was down for more
than half the token's life, or the ServiceAccount was deleted — and only
`cloop remote kube renew` (or, if the ServiceAccount is gone, `revoke --force`)
moves it on.

**`asked to upgrade the connection`** — `kubectl exec`, `attach`, `port-forward`
or `proxy`, or a client configured to watch over websockets. Ordinary watches
(`kubectl get -w`) work; nothing needs changing for them.

**`this cloop Kubernetes session has expired; the hub issues a fresh one at the
start of each dispatch`** — the run outlived `session_minutes`. Raise it (ceiling
720) or shorten the task. The token was genuinely correct, which is why this
message differs from the unauthenticated one.

**`no valid cloop Kubernetes session: the credential is missing, unknown, or has
been revoked`** — the lease was released, or nothing is sending the token at all,
or the hub restarted and the session was not restored: its run was not adopted
within 60 seconds of the request, or the session was refused when it was — its
grant revoked or expired while the hub was down, or it lapsed. The cases are
deliberately not distinguished to the caller; the session's
`kubeguard.session_closed` row says which.

**A lease fails with `executors.kube_guard is enabled but the Kubernetes access
monitor is not running`** — the section is on and start-up failed. The hub
printed why at boot. This is a refusal, not a fallback, on purpose. The run
starts without the kubeconfig, and since Task 20413 says so on the project's
Activity tab as a `credential_refused` event naming the run.

**`secret_files[N] repeats path …/kubeconfig`** — a hub from before Task 20413
delivering two kubeconfig grants to one project. A current hub merges them into
one document ([several grants, one document](#several-grants-one-document)).

**`grant … cannot be honoured under this hub's kube_guard policy …`** — the
hub-wide floor and the grant have nothing in common on some dimension. The tail
of the message says which: `policy permits no verbs` for the verb set, or
`namespaces: the grant asks for … but this hub's policy floor allows only …` for
a glob list. Every dimension refuses rather than defaulting. Widen the floor, or
narrow the grant to a literal subset of it; see
[the floor](#the-deployment-floor-and-the-grant-intersect).

**The delivery is not monitored at all** — `cloop secret lease` shows the
material without `via monitor`. Either `executors.kube_guard.enabled` is false,
or the lease was built by a path that does not attach the monitor. The hub's
start-up line is the authority on which of the two.

---

## See also

- [Security model](../security/model.md) — the trust boundaries and the
  guarantee → test table
- [Threat model](../security/threat-model.md) — STRIDE per boundary, with the
  residual-risk column
- [Git interception proxy](../git-interception-proxy.md) — the same inversion for
  git, and the package this one is shaped after
- [Secret and egress grants](../guides/secrets.md#kubeconfig) — how the
  kubeconfig the monitor holds is granted in the first place
- [Executor architecture](executors.md) — where a sandbox comes from, and the
  hub's own cluster credential
- [Configuration](../reference/configuration.md#kubernetes-access-monitor) —
  `executors.kube_guard` alongside the other executor sections
- [`pkg/kubeguard/policy.go`](../../pkg/kubeguard/policy.go) — the decision this
  document expands on
