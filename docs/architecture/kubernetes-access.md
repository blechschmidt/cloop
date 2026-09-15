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

The monitor runs **inside the hub process** and is **off by default**. An
unconfigured hub behaves exactly as [the hole it closes](#the-hole-it-closes)
describes: the cluster credential is delivered into the sandbox, minimised to
the contexts the grant allows, and the namespace list is a suggestion. Setting
`executors.kube_guard.enabled: true` turns it on, and from then on every
kubeconfig grant the hub delivers is a monitor session instead. See
[turning it on](#turning-it-on).

This is the same bargain the [git interception proxy](../git-interception-proxy.md)
makes for git, and the two packages are deliberately shaped alike.

- [The hole it closes](#the-hole-it-closes)
- [The inversion](#the-inversion)
- [What a request is, and how it is decided](#what-a-request-is-and-how-it-is-decided)
- [The policy](#the-policy)
- [Creating a read-only grant, end to end](#creating-a-read-only-grant-end-to-end)
- [Turning it on](#turning-it-on)
- [What it enforces, and what it does not](#what-it-enforces-and-what-it-does-not)
- [Audit events and metrics](#audit-events-and-metrics)
- [Troubleshooting](#troubleshooting)

---

## The hole it closes

With the monitor off — the default, and what an un-configured hub does — a
kubeconfig grant is delivered by rewriting the document. `MinimizeKubeconfig`
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
credential that points at a file path on the control-plane host.

### What a leaked session token is worth

| Leaked | Worth |
| --- | --- |
| **Session token** | Exactly the policy, for the remaining TTL, against **one** cluster, through **one** monitor. Under the default: get, list and watch, in the granted namespaces, with no exec, no port-forward, no writes, and nothing at all once the TTL lapses or the lease is released. Meaningless against the API server directly — it is not a credential the cluster has ever heard of. |
| **Kubeconfig delivered into the sandbox** — what an un-configured hub still does | Whatever that cluster's RBAC grants the uploading user, which on a personal kubeconfig is frequently cluster-admin: every namespace, every verb, `exec` into any pod, from anywhere on the network, until somebody rotates the credential — which means rotating it for the human it belongs to as well. |

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

`Policy.Decide` runs six checks, in an order chosen for the message the operator
reads rather than for speed: the most specific and most alarming reason wins.

1. **A dangerous subresource**, whatever the verb.
2. **A protocol upgrade.**
3. **A non-resource URL** — readable only, and only if it is in the allowlist.
4. **The verb.**
5. **The resource.**
6. **The namespace.**

### Subresources that are not data

Four subresources are refused for **every** verb and cannot be opted back into
by any policy:

| Subresource | What it actually is |
| --- | --- |
| `exec` | a shell inside the pod |
| `attach` | a shell on a process already running in it |
| `portforward` | a tunnel to anything the pod can reach, which on a cluster network is usually everything |
| `proxy` | arbitrary requests to the kubelet or a Service, laundered through the API server's credential |

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
    listen_addr: "0.0.0.0:8444"                  # where the monitor binds
    advertise_url: "https://hub.internal:8444"   # what the SANDBOX connects to
    cert_file: /etc/cloop/tls/kube-guard.crt
    key_file: /etc/cloop/tls/kube-guard.key
    ca_file: /etc/cloop/tls/kube-guard-ca.pem    # empty falls back to cert_file
    min_tls_version: "1.2"                       # or "1.3"; empty means 1.2
    session_minutes: 60                          # 0 means 60; ceiling is 720
    # A hub-wide floor. Empty lets each grant speak for itself.
    verbs: [get, list, watch]
    namespaces: ["team-*"]
    resources: ["pods", "services", "configmaps", "apps/deployments"]
```

Resource patterns name the resource, never a subresource: `pods` already admits
`pods/log`, and a pattern written as `pods/log` matches nothing at all, because
the string a pattern is matched against is `resource` for the core group and
`group/resource` otherwise.

- **Off by default.** Interposing a monitor changes the server a sandbox's
  `kubectl` talks to, so it is an operator's decision rather than something a
  config file acquires on upgrade.
- **TLS is required.** The session token rides an `Authorization` header on
  every request, and cleartext would publish it rather than deliver it. An
  enabled section without both `cert_file` and `key_file` is switched **off** at
  load rather than serving tokens in the clear.
- **`ca_file` is the one place this is easier to deploy than the git proxy.** A
  kubeconfig can carry its own trust anchor, so the PEM is embedded into the
  delivered document as `certificate-authority-data` and a self-signed hub
  certificate needs no change to the sandbox image. Empty falls back to
  `cert_file`, which is the right answer for a self-signed certificate and
  harmless for a publicly-signed one.
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
| `kubeguard.enabled` | The monitor is off while Kubernetes access is configured, so grants deliver the cluster credential and enforce nothing. A pass states the policy and session length actually in force. |
| `kubeguard.tls` | `cert_file`, `key_file` or `ca_file` missing or unreadable — the monitor will not start and every kubeconfig lease will be refused. |
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

### Where it runs, and why there is no `cloop kube-guard`

The monitor is a background service of the hub process, started from
`bootstrapExecutors` (`pkg/ui/kubeguard.go`) alongside the git proxy. There is no
standalone command, and that is a property of the design rather than an omission.

Sessions live in a `kubeguard.Registry`, which is memory, and they hold the
cluster credential. **The process that mints must be the process that serves.** A
separate `cloop kube-guard` would authenticate against an empty registry and
refuse every request the hub had authorised. The alternative that would make one
work is a shared session store, which means a kubeconfig at rest in a second
place for a topology nobody has asked for.

It follows that the monitor is a process-wide singleton and must start before any
executor registers, for the same reason the git proxy does: a broker constructed
before the monitor existed would route nothing.

---

## What it enforces, and what it does not

**Enforced, outside the sandbox, on every request:**

| | |
| --- | --- |
| Verb allowlist | `create`, `update`, `patch`, `delete`, `deletecollection` are refused under the default. |
| Namespace allowlist | Both directions: a named namespace outside the list, and a request that names none while a list exists. |
| Resource allowlist | When set, matched as RBAC spells it. |
| Non-resource URLs | Readable only, and only inside the allowlist; discovery by default. |
| Dangerous subresources | `exec`, `attach`, `portforward`, `proxy` — refused for every verb, not configurable. |
| Protocol upgrades | Refused. SPDY and websocket both. |
| Impersonation | `Impersonate-*` stripped, never forwarded. |
| Request body size | Bounded at 3 MiB by default, and **refused rather than truncated**: a declared `Content-Length` over the cap is rejected before a byte is read, and a chunked body that runs over is cut with `body_too_large`. Truncating was worse than either — the API server answered with its own parse error, so the sandbox was told its JSON was malformed when its request was simply too large. Under the default read-only policy no request has a body at all. |
| Session lifetime | TTL-bounded, and revoked when the lease is released. |

**Not enforced, and worth saying plainly:**

- **The cluster's RBAC is still the ceiling.** The monitor can only narrow. If
  the granted credential cannot read `secrets` in `team-a`, a policy that permits
  it does not make it work — the API server's own 403 is forwarded back.
- **Response content is not filtered.** A permitted `get secrets` in a permitted
  namespace returns the secret. The monitor decides *which requests*, not *what
  comes back*; narrowing that is what `resources` and the namespace list are for.
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
| `request_denied` | policy refused a request | **The row that matters.** The only place a sandbox's attempt to write to, or read outside, its granted scope is written down. Nothing else in cloop would record it. Alert on it. |
| `request_allowed` | a request was forwarded | Sampled, and **off** in the shipped hub: a `kubectl get pods` is several requests and a watch is one that never ends, so a row per allowed request would bury the denials in discovery traffic. |
| `session_minted` | a session was created | `Detail` carries the policy summary and the expiry. |
| `session_closed` | a session was revoked, released or reaped | `Detail` carries the reason and the allowed/denied counters. |
| `rejected` | refused *before* a session was identified, or a hub-side failure | No credential, an unknown token, an expired or revoked session, an unreachable cluster. Distinct from `request_denied`: nothing here got as far as a policy decision. |

`OnEvent` runs on the request goroutine, so a slow sink delays a sandbox's API
call. The hub's own sink does a single insert for that reason.

They land in the same hash-chained `audit_events` table as the credential broker,
with `entity_type` `kubeguard`, the session id as the entity, and the kind
prefixed: `kubeguard.request_denied`, `kubeguard.request_allowed`,
`kubeguard.session_minted`, `kubeguard.session_closed`, `kubeguard.rejected`.

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
`protocol_upgrade`, `body_too_large` and `unauthenticated`.

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

---

## Troubleshooting

**`Unable to connect to the server: x509: certificate signed by unknown
authority`** — the delivered kubeconfig's `certificate-authority-data` does not
match what the monitor presents. Set `ca_file` to the issuing CA's PEM; with it
empty the hub embeds `cert_file` itself, which is right for a self-signed
certificate but not for one signed by a private CA whose chain matters.

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

**`asked to upgrade the connection`** — `kubectl exec`, `attach`, `port-forward`
or `proxy`, or a client configured to watch over websockets. Ordinary watches
(`kubectl get -w`) work; nothing needs changing for them.

**`this cloop Kubernetes session has expired; the hub issues a fresh one at the
start of each dispatch`** — the run outlived `session_minutes`. Raise it (ceiling
720) or shorten the task. The token was genuinely correct, which is why this
message differs from the unauthenticated one.

**`no valid cloop Kubernetes session: the credential is missing, unknown, or has
been revoked`** — the lease was released, the hub restarted (sessions are in
memory and do not survive it), or nothing is sending the token at all. The three
cases are deliberately not distinguished to the caller.

**A lease fails with `executors.kube_guard is enabled but the Kubernetes access
monitor is not running`** — the section is on and start-up failed. The hub
printed why at boot. This is a refusal, not a fallback, on purpose.

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
