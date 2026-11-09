# Git proxy architecture

This page describes how cloop's git interception proxy fits into the hub, and
how each kind of sandbox (a Pod, a local container, an edge device, or a virtual
executor on one) is made to use it instead of the forge.

What the proxy decides (the policy model, ref patterns, how git sees a refusal,
the session model, and what it does not check) is in the
[git interception proxy](../git-interception-proxy.md) reference. This page
covers how it is wired up, what each executor does, what the sandbox holds and
for how long, how it fails and how to observe it. It ends with the
[limits that remain](#limits-that-remain), which matter when you plan a
deployment.

In short:

- **One process.** The proxy, its registry of live sessions, and both code paths
  that mint sessions run in the hub process, `cloop ui`. There is no separate
  daemon, and there can't be one (see
  [the minting process must be the serving process](#the-minting-process-must-be-the-serving-process)).
- **Two paths.** cloop's own git (the fetch that provisions a project's source
  before a task) reaches the proxy through a wrapped workspace credential. The
  workload's git (whatever the agent clones and pushes) reaches it through a
  GitHub lease rewritten to point there. Each path mints its own kind of
  session, and different events end them.
- **One rule.** While the proxy runs, the hub puts no forge credential (PAT or
  GitHub App installation token) into any sandbox it dispatches. If a valid
  proxy section is configured but the proxy is not running, GitHub access fails
  closed and the credential is never handed over instead. This includes every
  process other than `cloop ui`, none of which runs a proxy.

- [One process, and why](#one-process-and-why)
- [Two paths into one proxy](#two-paths-into-one-proxy)
- [The policy a session carries](#the-policy-a-session-carries)
- [The push scan](#the-push-scan)
- [Executor by executor](#executor-by-executor)
- [What the sandbox holds](#what-the-sandbox-holds)
- [Which credential reaches the sandbox](#which-credential-reaches-the-sandbox)
- [The network between sandbox and proxy](#the-network-between-sandbox-and-proxy)
- [How long a session lives](#how-long-a-session-lives)
- [How it fails](#how-it-fails)
- [Observing it](#observing-it)
- [How it is tested](#how-it-is-tested)
- [Limits that remain](#limits-that-remain)

---

## One process, and why

```
 hub process: cloop ui
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │ bootstrapExecutors                                                          │
 │  └─ ensureGitProxy(cfg, dir)  once per process, before any executor exists  │
 │       cfg: config.yaml with this hub's config.ui-<port>.yaml merged in      │
 │       └─ startGitProxy ─▶ gitProxyService  (process singleton)              │
 │            ├─ TLS listener (pkg/tlsconf) ◀─────────────── sandboxes' git    │
 │            ├─ gitproxy.Proxy     smart-HTTP handler, policy per ref ─▶ forge│
 │            ├─ gitproxy.Registry  live sessions, in memory                   │
 │            ├─ Registry.Store     lease-path session records, no credential  │
 │            ├─ reaper             drops lapsed sessions every 5 minutes      │
 │            └─ audit sink ──────▶ audit_events (control-plane database)      │
 │                                                                             │
 │ who mints sessions in that registry                                         │
 │  ├─ gitproxycreds.Source   workspace path: wraps the credential source of   │
 │  │                         the Kubernetes driver and of every edge device   │
 │  └─ gitGuard               lease path: a secretbroker.GitGuard attached to  │
 │                            every broker the hub opens to lease grants       │
 │                                                                             │
 │ who ends them                                                               │
 │  ├─ secretLease.Close ─▶ closeGuardedSessions   a lease is released         │
 │  ├─ Registry.ReapExpired                        a session's TTL lapsed      │
 │  └─ gitProxyService.Close                       the hub shuts down          │
 └─────────────────────────────────────────────────────────────────────────────┘
```

| Piece | Where | Role |
| --- | --- | --- |
| `executors.git_proxy` | `pkg/config/gitproxy.go` | The configuration section. `GitProxyConfig.Policy()` turns it into the hub's policy: `allowed_refs` (default `refs/heads/cloop/**`), create and update, delete only with `allow_delete`, fetch always. Read once at startup from the hub's effective configuration (`.cloop/config.yaml` with the hub's per-instance `config.ui-<port>.yaml` overlay merged in), so one of two dashboards sharing a directory can run the proxy without the other. There is no dashboard setting. See [turning it on](../git-interception-proxy.md#turning-it-on). |
| `ensureGitProxy`, `startGitProxy` | `pkg/ui/gitproxy.go` | Start the proxy once per process, and record separately whether the configuration asked for one (`gitProxyRequired`), so a proxy that is wanted and one that is running are told apart. |
| the hub CA, `tls: auto` | `pkg/hubca`, `pkg/ui/hubtls.go`, `pkg/ui/hubca_api.go`, `cmd/hub_ca_cmd.go` | With `tls: auto`, the hub issues the proxy's (and the Kubernetes monitor's) certificate from its own CA. The CA is minted once per control plane, its key sealed under the KEK registry in `hub_tls`. Each monitor gets a 72-hour leaf that the cluster leader renews (`watchMonitorCertificates`) and every member re-reads each minute. A staged rotation (`hubca.Stage`, `Activate`, `RetirePrevious`, `Emergency`) replaces the CA online, and every member follows it within a minute (`hubCA.tick`). `SandboxGitCA` says which CA a dispatch trusts (both during a rotation) and for which URL; `labelHubCATrust` records it on the dispatch. |
| `gitproxy.Registry` | `pkg/gitproxy/session.go` | Sessions keyed by id, each holding `sha256(token)` (never the token), the upstream credential and the policy. No HTTP code. |
| upstream credential generations | `pkg/gitproxy/refresh.go` | A session minted with `MintRequest.Refresh` renews its upstream credential (a GitHub App token) from its own request path before it expires, one refresh at a time, and retires the old token once no request presents it. |
| App token slots | `pkg/secretbroker/apprefresh.go` | One per App grant in a lease: the token's current and superseded generations, and the scope it was minted at, which every refresh requests again. |
| `gitproxy.Proxy` | `pkg/gitproxy/proxy.go` | The three smart-HTTP routes. Authenticates, checks the repository, parses a push's command list, decides, and only then attaches the forge credential. |
| `gitproxycreds.Source` | `pkg/executor/gitproxycreds` | Wraps an `executor.WorkspaceCredentialSource`: leases as before but keeps the credential, mints a **pinned** session, and returns the session token with the proxy's URL for the repository. |
| `secretbroker.GitGuard`, `gitGuard` | `pkg/secretbroker/gitguard.go`, `pkg/ui/gitguard.go` | The interface through which a broker hands over a GitHub token. The hub's implementation mints a **scoped** session over the grant's repository allowlist and returns the credential the sandbox gets instead. |
| `deliverGuardedGitHub` | `pkg/secretbroker/githubguarded.go` | Writes a guarded GitHub lease: a session credential file, a credential helper, and a gitconfig that rewrites GitHub URLs to the proxy. |
| `gitProxyAuditSink` | `pkg/ui/gitproxy.go` | One row per decision in the hash-chained audit trail, or a `git-proxy:` line on stderr when the database is unavailable. |

### The minting process must be the serving process

A session is minted when a workload is dispatched and authenticated when its
git connects, possibly much later. The registry lives in memory, so a
`cloop git-proxy` command in another process would find it empty and refuse
every request the hub had authorised. A shared store would not help: serving a
session needs the forge credential it presents, so the store would hold that
credential at rest a second time. The proxy therefore runs inside the hub, as a
process-wide singleton for the same reason as the executor registry: two
`Server` instances in one process share their executors, so they must share the
sessions those executors' sandboxes present.

The hub does record everything about a lease-path session except the
credential: its id, the SHA-256 of its token, its scope and deadline, and which
hub process serves it. If that process stops, the one that adopts the run can
restore the session and derive its credential again from the run's lease. A
workspace's pinned session, which stands on its own workspace lease, is
recorded the same way. See [a hub restarted mid-run](#a-hub-restarted-mid-run).

The [Kubernetes access monitor](kubernetes-access.md) keeps its own registry in
the same process for the same reason, and works the same way.

### Why it starts first

`ensureGitProxy` runs at the top of `bootstrapExecutors`, before the configured
executors are reconciled. Reconciliation gives the Kubernetes driver its
workspace credential source once, for the life of the process, so a proxy
started later would route edge devices but miss every Pod, without any warning.
Edge devices are wrapped one by one, as the hub builds each device's credential
source (`workspaceCredentialFactory` in `pkg/ui/workspace.go`), and leases per
broker, as each broker is opened (`attachGitGuard`). Both read the singleton
when they need it.

Only `cloop ui` starts a proxy, so only `cloop ui` can give the Kubernetes
driver a wrapped source. Every other process that registers that driver (`cloop
serve`, `cloop hub doctor`, the CLI's own subcommands) gets a source that
refuses git workspaces while `executors.git_proxy` is enabled
(`routeWorkspaceSource` in `pkg/executor/reconcile`), so no Pod is handed the
forge credential. `cloop serve` reports this at startup.

### Two seams, so nothing below the hub knows

No driver imports `pkg/gitproxy`, and neither does `pkg/secretbroker`:

- **The workspace path is a decorator.** Interception depends on the
  deployment, not the grant: the same GitHub grant works with or without a
  proxy. `pkg/executor/gitcreds` decides which grant authorises a repository,
  `gitproxycreds` adds how the sandbox reaches it, and a driver sees only an
  `executor.WorkspaceAccess`: a credential and the URL it is valid for, always
  together.
- **The lease path is an interface.** The broker is the lower layer and also
  serves workloads that have nothing to do with git, so it must not import the
  proxy. Through `GitGuard` the broker offers a token and gets back a substitute
  credential, an explicit "not guarding this one" (on a hub with no proxy), or
  an error, which drops the GitHub material from the lease.

---

## Two paths into one proxy

| | Workspace path | Lease path |
| --- | --- | --- |
| **Whose git** | cloop's own: the fetch that sets up the project's source before the harness starts, and the write-back push after it when a Spec asks for one | the workload's: `git clone`, `git fetch`, `git push`, submodules, `go get`, whatever the agent runs |
| **Which grant** | a GitHub grant that covers the project's own repository (see [granting a PAT for workspace provisioning](../guides/secrets.md#granting-a-pat-for-workspace-provisioning)) | every `github_pat` and `github_app` grant to the project (see [GitHub repositories and PATs](../guides/secrets.md#github-repositories-and-pats)) |
| **Minted by** | `gitproxycreds.Source.ForWorkspace`, in the driver, at dispatch | `gitGuard.GuardGitHub`, while the broker builds the run's lease, at dispatch |
| **Session shape** | **pinned** to the workspace's `owner/name` | **scoped** to the grant's `owner/name` glob allowlist |
| **Upstream** | the grant's forge host and the workspace's `owner/name`; the origin must be on that host ([one route per forge host](#one-route-per-forge-host)) | the grant's forge host: `https://github.com`, or the GitHub Enterprise Server its secret names |
| **Policy** | the hub's, with the grant's branch list as `RestrictRefs` | the hub's, narrowed by `guardPolicy` (see [below](#the-policy-a-session-carries)) |
| **Reaches git as** | a credential in the environment of one git child process, as an origin-scoped `http.<origin>.extraHeader`, never on disk | three files in the lease directory and a few environment variables |
| **How git finds the proxy** | the workspace's `Repo` is replaced by `Minted.RepoURL`, so the fetch and any push go to the proxy | the lease's gitconfig rewrites `https://<host>/`, `git@<host>:` and `ssh://git@<host>/` to the proxy's route for that host: the proxy's base URL for `github.com`, and `/_forge/<host>` beneath it for any other host |
| **Ended by** | the driver handing it back when the run is done with it (after the fetch, or once the workload has ended and its write-back has run), or its lease being revoked. Until then it is renewed `session_minutes` at a time, so the TTL ends it only if nothing renews it. Its lease is kept alive while it lives and released when it ends. A hub that stops suspends it; after a restart the adopting member renews it and ends it with the workload | the release of the lease that minted it, or else its TTL (see [how long a session lives](#how-long-a-session-lives)) |
| **Session actor** | `ui` | the credential's owner for a personal secret, otherwise the lease's actor |

### The workspace path

```
hub, at dispatch                                 edge device / Pod
────────────────                                 ─────────────────
the driver asks its credential source for the workspace
  gitproxycreds.Source.ForWorkspace
    ├─ inner source leases the grant, as held by a proxy
    ├─ the origin must be on the grant's forge host, or nothing is minted
    ├─ Registry.Mint  pinned to owner/name, upstream = https://<grant's host>/owner/name,
    │                 RestrictRefs = the grant's branches
    └─ WorkspaceAccess{ session id + token,
                        Repo = https://<proxy>/owner/name }
the driver ships it ─────────────────────────────▶ provisioning fetch
                                                    git fetch https://<proxy>/owner/name
                                                    (credential on this git child only)
                                                  the harness runs
proxy: authenticate ─ repository pin ─ [push: parse commands ─ policy ─ audit]
       ─ attach the forge credential ─ forward
```

If the inner source offers `HeldSource.ForProxiedWorkspace`, as
`gitcreds.BrokerSource` does, the decorator calls it. That marks the lease
request `GitHubProxied`: the credential will stay on the hub. This is what lets
a grant limited to certain branches keep push access. The broker withholds push
access from a branch-restricted GitHub credential going into a sandbox, since
nothing in a sandbox can restrict pushes by branch, but the proxy can.

Four things the decorator does:

- **It fails closed.** If a session cannot be minted, the dispatch fails and the
  inner lease is released. There is no fallback to the direct credential.
- **A public repository passes through.** An empty credential means an
  anonymous fetch, so there is nothing to protect and no session is minted.
- **The lease lives as long as the session.** The registry's `OnEnd` hook
  releases the inner lease when the session ends (closed, reaped after its TTL,
  or closed with the hub), not when the driver has delivered the credential.
  For a `github_app` grant, releasing the lease destroys the installation token
  at GitHub, while the session presents that token upstream for its whole life.
  Releasing at delivery would leave the session with a dead token, and on
  Kubernetes the fetch itself would fail. The release a driver is given closes
  the session only if nothing ever authenticated with it (a dispatch that failed
  before the fetch), so a used session keeps its TTL for the write-back.
- **The credential and the URL travel together.** A driver that used the token
  but ignored `Repo` would send the sandbox to the forge with a token the forge
  doesn't know. That fails with an error; it never falls back to the direct
  path.

[The security model](../security/model.md#workspace-provisioning) describes how
the credential is kept out of the Spec, argv, disk and logs on its way to the
git child. With the proxy, a session credential takes that route instead of the
forge token. The stored and audited copy of the Spec still names the real
repository, so a run row shows `github.com/acme/tool` and not a proxy URL whose
session ended with the run.

**In production, this path carries the fetch and, if the hub asks for it, the
write-back push.** With `executors.write_back: push`, an executor that does not
share the hub's filesystem returns a run's work by pushing it. Once the workload
has exited successfully, the device commits the run's changes to a new branch,
`cloop/run-<time>-<id>`, and pushes it to the project's origin through the
workspace's pinned session, so the proxy's ref policy decides the push. The
workspace is then fetched at the commit the hub's checkout records for
`origin/<branch>`, the base the push is measured from. A project without one is
dispatched without a write-back, and its journal says why. The outcome (branch
and commit, or the error) is a `write_back` row in the project's journal. `cloop task
reproduce` and `cloop hub doctor --smoke` ask for a bundle instead, which comes
back over the executor's own channel and needs no forge credential. Without the
setting, every push a running hub sees comes from a workload, on the lease path.

### The lease path

```
hub, at dispatch
  acquireSecretLease ─▶ Broker.LeaseFor(project, executor, run)
    github_pat: the token ──────────────┐
    github_app: an installation token   │   the App's private key never leaves the
                minted for this lease ──┤   hub; the token is recorded for
                                        │   revocation before anything can fail
                                        ▼
             GitGuard.GuardGitHub ─▶ Registry.Mint  scoped: the grant's allowlist,
                                                     upstream https://<grant's host>,
                                                     policy guardPolicy(...)
             deliverGuardedGitHub ─▶ git-proxy-credential, git-credential-cloop, gitconfig
  the driver puts the files in the sandbox's lease directory

sandbox, while the lease is live
  git clone https://github.com/acme/tool
    ├─ gitconfig: url."https://<proxy>/".insteadOf https://github.com/
    │             (a server's grant: url."https://<proxy>/_forge/<host>/".insteadOf https://<host>/)
    ├─ git asks the helper; it answers for the proxy's host and no other
    └─ GET https://<proxy>/acme/tool/info/refs?service=git-upload-pack
proxy: authenticate ─ acme/tool inside the allowlist? ─ … ─ forward to
       https://github.com/acme/tool.git with the token

lease released ─▶ closeGuardedSessions ─▶ Registry.Close(id, "lease released")
```

The broker doesn't know what is behind the interface. From the result it takes
the substitute credential, whether the session is read-only, and the ref
patterns a push must match (the last two only to tell the workload). It checks
one thing: a guard that returned the token it was given would undo the exchange
while looking like a working one, so `deliverGuardedGitHub` compares the two in
constant time and refuses a match.

For a `github_app` grant the order matters. The installation token is minted
first, with the grant's full permissions since the proxy enforces the branch
list, and recorded for revocation before either delivery branch can fail. Every
token that exists at GitHub is therefore one the hub knows to destroy. If the
guard then fails, the token is revoked at GitHub at once.

### Where the two paths meet

A project whose directory is a checkout of a granted repository uses both. An
edge device provisions it through a pinned session and leaves `origin` pointing
at the proxy's URL for that repository, with no credential in `.git/config`.
When the workload later pushes from the checkout, its git asks for a credential
for the proxy's host, and the lease's helper, which answers for that host only,
supplies the lease's session. The proxy finds the repository in the grant's
allowlist and applies the lease's policy.

So two sessions cover one repository: the pinned one for cloop's own fetch, and
the scoped one for everything the workload does. Device checks `WS2` and `WS3`
in [the live kit](#on-a-real-device) test the first (the provisioned origin is
the proxy and holds no credential), and `WS4` and `WS5` the second (the
workload's pushes from it follow the grant).

### One route per forge host

A session presents its credential to one forge host only, the grant's:
`github.com` for a `github_pat` unless the secret recorded a GitHub Enterprise
Server host, and for a `github_app` the web host of its `base_url`
(`https://ghes.example.com/api/v3` means `ghes.example.com`). `GitGuardRequest`
carries the host, `MintRequest.ForgeHost` records it on the session and its
durable record, and the session's upstream is on it. Builds before v0.0.6
lacked this: a project whose origin named `https://attacker.example/acme/tool`
got a pinned session that presented the forge token there, and an enterprise
App's token went to `https://github.com` whenever a workload cloned a
`github.com` URL with the same `owner/name`.

On the workspace path the origin must be on the grant's host, or no session is
minted and the dispatch is refused with an error naming both hosts.
`pkg/forgehost` compares them, ignoring case, a trailing dot, the default port,
userinfo and the Unicode spelling of an internationalised name, and nothing
else. The upstream is then built from the grant's host and the repository's
path, never from the origin's spelling of them.

On the lease path each host gets its own rewrite to its own route through the
proxy: the proxy's base URL for `github.com`, and `/_forge/<host>/` under it for
any other host.

```
url."https://<proxy>/".insteadOf                       https://github.com/
url."https://<proxy>/_forge/ghes.example.com/".insteadOf https://ghes.example.com/
```

The proxy accepts a request on a host's route only with a session for that
host, and on the base URL only a pinned session (whose URL already fixes its
repository and host) or a scoped `github.com` one. Anything else is refused
before a byte is forwarded, and the rejection row names the session's host.
When a lease holds several GitHub grants, each credential helper answers only
under its own host's route, so a lease with a `github.com` grant and an
enterprise grant for the same `owner/name` never presents either token to the
other host. Routes spell hosts as `gitproxy.ForgeRoute` renders them, and the
proxy serves no other spelling. A guard that would give a non-`github.com` grant
no route of its own fails the lease instead of sharing `github.com`'s.

A durable session record written before hosts were recorded is read as what it
was minted for (`github.com` for a scoped session, its upstream's host for a
pinned one). A restore holds it to the host the grant's secret names now, which
`Broker.GitHubGrantHost` reads from the PAT's payload or the App token slot's
recorded API base before anything is minted. A record, origin or slot that
disagrees is refused with an error naming the hosts.

Only `github.com` and GitHub Enterprise Server hosts receive brokered
credentials, on either path. A repository on any other forge is fetched
anonymously or refused.

---

## The policy a session carries

A session's policy starts as the hub's and can only get narrower on its way to
a sandbox. [Narrowing by grant](../git-interception-proxy.md#narrowing-by-grant-restrictrefs)
has the rules; this table shows which path applies each step.

| Dimension | Workspace path | Lease path (`guardPolicy`) |
| --- | --- | --- |
| Ref allowlist | the hub's `allowed_refs` | the same, as a copy (never shared) |
| Create, update | as the hub allows | removed unless the grant has `contents:write` (or `contents`, or `*`). A PAT grant with no `--permissions` is read-only, whatever the PAT itself could do |
| Delete | as the hub allows (`allow_delete`) | never, whatever the grant or the hub says |
| Branches | the grant's list becomes `RestrictRefs` | the same, and only on a session that can write |
| Fetch | inherited (the hub's policy always allows it) | inherited, never forced on |

`guardPolicy` copies the hub's allowlist before narrowing anything. `Policy` is
copied by value but shares its slice, so a change written through the shared
backing array would narrow the hub's policy for every later session. For the
same reason, `gitproxycreds` clears `RestrictRefs` before setting it, so one
grant's branch list never reaches the next workspace's session.

**The workload is told the result.** A guarded lease sets
`CLOOP_GIT_PROXY_MODE` (`read-only` or `read-write`) and, on a session that can
push, `CLOOP_GIT_PUSH_REFS` (the hub's ceiling) and `CLOOP_GITHUB_PUSH_BRANCHES`
(the grant's list). `cloop run` reads them in `pkg/pm/repoaccess.go` and writes
the task prompt's *Repository access* section from them, so the agent picks a
branch the proxy will accept instead of discovering the policy through refused
pushes. For a read-write grant on `acme/tool`, on a hub with the default
ceiling, the whole section reads:

```text
## REPOSITORY ACCESS
This run has been granted access to these GitHub repositories:
- `acme/tool` (read and write)

When the task refers to "the repository" or "the repo" without naming one, it means `acme/tool`.
These repositories are not checked out here unless you can see them in the working directory. Clone the one you need into the working directory by its plain https URL:
    git clone https://github.com/acme/tool
git is already configured to authenticate for them: do not ask for, create, print or store a token, and do not change the remote URL.
Work that is committed but not pushed stays on this machine, where nobody will see it: to deliver a change, commit it in the clone and push it to that clone's origin. Pushes pass through cloop's git proxy, which accepts only branches matching `cloop/**`. Commit on a branch that matches — for example `cloop/<short-description>` — push that branch, and name it in your summary.
```

The instruction not to change the remote URL matters. The rewrite happens in
git's transport, so a clone's `origin` still reads `https://github.com/acme/tool`.
A workload that changed it to point anywhere else would bypass the rewrite and
find no credential.

---

## The push scan

A workload has its leased credentials in plaintext, because it needs them: the
env secrets it was granted, the bearer token in its kubeconfig, its registry
auth, its egress proxy's password. If it commits one and pushes it, the
credential is published, possibly in a public repository. GitHub's push
protection only knows vendor formats, and only where it is enabled; an internal
API key granted as an env secret matches none of them. So the proxy reads every
push the policy allows on its way to the forge, and refuses one that carries a
credential its run was given.

### What a push is scanned for

The exact values the hub delivered to the session's run, which the hub knows
and no registry of credential formats can:

| Delivered as | Matched |
| --- | --- |
| An env secret | every value the grant delivers |
| A kubeconfig | each user's bearer token, client key (as `client-key-data` and as its PEM, line by line), basic-auth password, auth-provider tokens, and an exec plugin's env values whose names say token, secret, password, key or credential. Under the Kubernetes monitor, also the monitor session's token in the delivered kubeconfig and, as defence in depth, the cluster credential the monitor presents upstream |
| A registry secret | each registry's `auth`, the password inside it, `password`, `identitytoken`, `registrytoken` |
| An egress proxy secret | the proxy URL and its password |
| The run's egress proxy session, its model relay session | the proxy URL and its password; the relay token |
| A GitHub PAT or App grant | the git proxy session token the sandbox holds and, as defence in depth (the sandbox never held it), the PAT or App token the hub presents upstream |

Each value is matched as delivered; base64-encoded in both alphabets, at all
three byte alignments (so a value inside a larger encoded blob, such as a
`.dockerconfigjson` or a Kubernetes Secret manifest, is found as well as one
encoded on its own); and percent-encoded as a query value, a path segment and
URL userinfo. Values shorter than eight bytes are not matched, because they
would refuse pushes for no security benefit. pkg/secretbroker splits each
delivered document into its values (`Lease.CredentialValues`), because most of
a document's bytes (a credential helper script, a gitconfig, a CA certificate)
are not secret and turn up in every repository. Certificates and server
addresses are never matched.

`executors.git_proxy.push_scan: shapes` also matches pkg/redact's registry of
credential formats, the same detectors `cloop audit` uses. It is opt-in because
repositories carry realistic fake keys in their test fixtures (cloop's does; see
the GH013 refusals in its history), and a mode that refused those would get
switched off.

### How the pack is read

`pkg/gitproxy/packscan.go` reads the pack as it streams: the header, then each
object's varint header and zlib stream, inflated through a fixed buffer and then
discarded. It handles v2 and v3, SHA-1 and SHA-256, and reads commits, trees,
blobs and tags in full. For an `OFS_DELTA` or `REF_DELTA` it reads the delta's
instructions and scans the bytes they insert. A copied range comes from an
object that is either in the same pack, where it was scanned itself, or already
on the forge, where it was published before this push. Ref names in the command
section and push options are scanned too, since a branch named after a
credential publishes it as a file would.

Wherever index-pack's rules decide what the forge will see, the reader follows
them: header widths, the bounds on a base offset, a zlib stream ending where
zlib says it ends, the inflated size matching the header, and patch_delta's
rules for a delta's instructions. A reader that parsed a pack differently from
git could scan bytes the forge does not store. Anything the reader cannot parse
is refused, not forwarded.

The matcher makes one pass however many values there are. Each pattern is
anchored on its last eight bytes, which the stream keeps as one 64-bit word. At
each position that word is tested against a filter, and the full pattern is
compared only on a hit, over a rolling window as long as the longest pattern. A
run of consecutive inserts is one stream. A copy ends it, because in the object
git builds, the copied bytes sit between the inserts on either side.

### The decision comes before the forge's

The forge receives the pack as the scan reads it, never ahead of the scan,
except for the pack's trailing checksum: the reader holds back everything from
the checksum on until the scan ends. receive-pack does not accept a pack
without it, and git updates no ref without unpacking the pack first. If the scan
passes, the checksum is released and the forge gets the bytes git sent,
unchanged. If it refuses, the proxy cuts off the forge's request mid-body (over
HTTP/1.1 by closing the connection before the chunked body's terminator, over
HTTP/2 by resetting the stream). The forge discards the incomplete pack in its
quarantine, and no ref moves. `TestPushScanRefusesALeasedValueInAFile` and
related tests check this against a real `git-http-backend`: the ref did not
move, and the pushed objects are not in the repository. Bytes after the checksum
are refused too, and stay held back: git ignores them, and forwarding the
checksum ahead of them would give the forge a complete pack.

The sandbox's git gets the refusal as ordinary git output, on the side band if
it asked for one:

```text
remote: cloop git proxy refused this push: it carries a credential this run was given.
remote: - blob 6b937d358371 (deploy.env) in commit 40ee89e6633e: env ACME_API_KEY (secret "acme-api", grant gr_e2e)
remote: Take the value out of these objects and rewrite the commits that carry it (git commit --amend, git rebase -i), then push again.
remote: No ref was updated, and the forge never received a complete pack. The value itself is never shown, logged or recorded.
 ! [remote rejected] HEAD -> cloop/task-1 (carries a credential this run was given: env ACME_API_KEY (secret "acme-api", grant gr_e2e))
```

A finding names the object id, the commit that carries it, and the grant, the
secret and the part of the delivery the value came from. Where a tree in the
same pack names the object, the finding gives its path: the full path if every
tree above it arrived whole, or only the file name if the tree that names it
arrived as a delta, which is usual in an incremental push. A delta's own id
would need its base, which may be on the forge, so a delta is named by its base.
The run's values are removed from everything the report names before it is
printed, since a directory, a tag or a branch can be named after one. Up to
sixteen findings are reported; the scan stops looking after that.

### Bounds

The reader inflates as a stream with a window as long as the longest value, so
memory does not grow with the push. Three settings cap what a push may cost:
`push_scan_max_object_mb` (1024) per object; `push_scan_max_push_mb` (4096) per
push, which stops a pack built to inflate a thousandfold from tying up a core;
and `push_scan_seconds` (300) of scanning, not counting time spent waiting on
the sandbox or the forge, so a slow link is no reason to refuse. The clock is
checked on every read from the sandbox and before every object, so a pack of
millions of empty objects, or one object of millions of empty deflate blocks,
also stops at the limit (`TestScanTimeLimitHoldsForObjectsThatInflateToNothing`,
`TestScanTimeLimitHoldsInsideAnObjectOfEmptyBlocks`). The bytes read from the
sandbox are held to the session's `max_pack_bytes` both before and after a
gzipped body is decoded. A push over any limit is refused with an error naming
the limit and its setting, because a scan that gave up has not found the push
clean. One session's pushes are scanned two at a time, so a sandbox pushing in
parallel gets its scans in turn and cannot occupy every core of the hub. If the
sandbox or the forge abandons a push mid-scan (say the forge answers with an
error before it has the pack), the push is neither allowed nor refused: a
`gitproxy.rejected` row says it did not complete, and the sandbox gets the
forge's own answer.

On one core of an AMD EPYC, scanning a ~100 MiB pack that git wrote (449
objects, 180 MiB inflated: random binary blobs, source-like text, and a commit's
worth of deltas) takes 1.3 s in `values` mode and 4.0 s in `shapes` mode. Pushed
through the proxy with TLS on both legs, the same pack takes 0.48 s unscanned,
1.7 s with `values` and 4.5 s with `shapes`. Scanning and forwarding overlap
through a bounded queue, so a push takes about as long as the slower of the
two. `BenchmarkPushScanPack` and `BenchmarkPushThroughTheProxy` in
`pkg/gitproxy` measure this.

### Which values a session has

Each session is minted for a run (on the workspace path, through
`executor.WithDispatchRun`), and the hub records the run's values when it
dispatches it (`pkg/ui/gitproxy_pushscan.go`): every credential its lease
delivered, and every value its spec declares sensitive. They stay in that hub
process's memory only, and are never logged, persisted, audited or echoed. They
are kept until the run and every session naming it have ended, because a
workspace's write-back push can come after the run's own lease is released.

**After a restart** the process that adopts the run has neither its spec nor
its materials. It scans with the same two sets it scrubs the run's output with:

- **What the grants delivered, derived again.** `Broker.RedactionCredentials`
  rebuilds each grant's material through the delivery's own narrowing
  (`MinimizeKubeconfig`, the registry filter, the env key filter) and splits it
  with the code that splits a delivered lease, so the set equals what the lease
  delivered: env values, a personal access token, a kubeconfig's tokens and
  client keys, a registry's auth and the password in it, an egress proxy
  secret's URL and password (`TestRedactionValuesAreWhatTheLeaseDelivered`).
  These are matched as exact values, in every encoding above.
- **What the previous process minted, by hash.** The run's GitHub App
  installation token and the tokens of its git proxy, Kubernetes monitor,
  egress and model relay sessions were minted by the process that dispatched
  it, and none of them is stored in plaintext. Only a SHA-256 of each is stored:
  `proxy_sessions.token_sha256` for a session, and `app_token_slots.token_hashes`
  for every installation token a slot held, written before the token leaves the
  hub. Each kind starts with a prefix that names it (`cloop_git1_`,
  `cloop_kube1_`, `cloop_egress1_`, `cloop_relay_`, GitHub's `ghs_`), so the
  scan finds candidates by prefix, cuts each to its recorded length, and refuses
  the push only if one hashes to a token of this run. A token of the same form
  that is not the run's, such as a test fixture or another run's token, passes
  (`TestScanRefusesATokenKnownOnlyByItsHash`,
  `TestScanLeavesATokenOfTheSameShapeAlone`). As for a value, the refusal names
  the grant and secret behind the token.

Only an adopted run's pushes are searched for hashes. For a run it dispatched
itself, the process knows every value and scans for those
(`TestAnAdoptedRunIsHeldToEveryCredentialItWasGiven`).

Until the run ends, two things are not found: a session token minted before its
kind carried a prefix (in a run already going when its hub was upgraded to a
build that adds the prefixes), and a minted token in any encoding other than
the one it was minted in, since the hash is of the token itself.

### Configuration

`executors.git_proxy.push_scan` is `values` (the default whenever the proxy
runs), `shapes`, or `off`, which forwards packs unread. A project's own
`.cloop/config.yaml` may set a stricter mode for its pushes but never a weaker
one: a project that says `off` on a hub that says `values` is scanned for
values, and one that says nothing is scanned as the hub says. A workload whose
sandbox shares the project directory may have written that file, which is why
it can only tighten. The hub reads the one key from a regular file only,
without following a link or waiting on a FIFO, and treats a value it cannot
read as `values`.

---

## Executor by executor

Which of the two paths each backend uses, how the lease's files reach the
workload, and where git runs relative to the proxy:

| Executor | Workspace path | Lease files reach the workload | Where the workload's git runs | `advertise_url` must be reachable from |
| --- | --- | --- | --- | --- |
| `localprocess` | not used: a `bind` workspace, the operator's own checkout | the hub's own tmpfs directory (`/dev/shm/cloop-lease-…`), read in place | on the hub's host, as the hub's user | the hub's host; the loopback default works |
| `container` (runc, gVisor, Kata) | not used: a `bind` workspace | a per-run tmpfs the driver stages, bind-mounted read-only at `/run/cloop/cloop-lease-<slug>` | inside the container | the container's network, which is `none` unless configured |
| `kubernetes` | the `workspace` init container fetches (`cloop workspace provision`), wrapped at reconciliation; the per-run `cloop-ws-<handle>` Secret carries the session id as `CLOOP_WORKSPACE_USER` beside the token | a per-run `Secret`, projected read-only at `/run/cloop/cloop-lease-<slug>`: files `0400`, the credential helper `0550` so git can run it | in the harness container | the Pod network (the hub's `Service`) |
| `remote`, host mode | the agent fetches on the device before the harness starts, holding the session credential in its memory | the start frame's `secret_files`; the agent writes them into its own `cloop-lease-*` tmpfs and relocates the paths | on the device, as the agent's user | the device |
| `remote`, container mode, and every virtual executor | as in host mode: the fetch runs on the device host, never inside the container | as in host mode, then bind-mounted read-only into the container | inside the container on the device | inside that container: its network or firewall must admit the proxy |

Under [`tls: auto`](../git-interception-proxy.md#the-certificate-the-sandbox-has-to-trust)
the hub also attaches its CA to each dispatch (`applyGitProxyTrust`), and each
driver puts it where the workload's git reads it, trusted for `advertise_url`
only: a private file for `localprocess`, `/etc/cloop/hub-ca/ca.crt` (read-only,
from the run's lease Secret) for a container and a Pod, and the start frame's
Spec for a device. A device's provisioning fetch and write-back push trust it
too, and its agent must speak protocol v21, or the workload is refused with an
error naming the upgrade.

Some consequences of that table:

- **The `container` driver never uses the workspace path, but its sandboxes use
  the lease path.** A local container with a GitHub grant clones through the
  proxy like any other sandbox, and on the driver's default `network: none` it
  cannot reach the proxy at all.
- **On an edge device the two paths use different networks.** The provisioning
  fetch runs in the agent, on the device host, with the host's routing and the
  agent's environment. Its session credential travels in the start frame beside
  the Spec and never enters a container. The workload's own git runs wherever
  the payload runs: in container mode, behind the container's network and the
  executor's firewall. So a device can provision a workspace through the proxy
  and still have a sandbox that cannot reach it.
- **Virtual executors use their parent's credential source under their own
  identity.** A virtual executor has no workspace source of its own. Its
  dispatch goes through the parent device's, which leases as the virtual
  executor (`executor.WithRequestingExecutor`). The grant chosen before
  dispatch, the workspace lease and the workload's own lease therefore all
  match the same subject: a grant issued `--to executor:<virtual id>` provisions
  the workspace, and one issued to the parent device does not reach its virtual
  executors.
- **On `localprocess` there is no boundary for the proxy to enforce.** The
  workload runs as the hub's own user. The proxy still keeps the token out of
  the lease directory, but a process that can read the hub's database can read
  everything the proxy protects. `executors.allow_host_process: false` exists to
  rule this out; see
  [the no-host-execution guarantee](../security/model.md#the-no-host-execution-guarantee).
- **Features always run on the host.** [Parallel features](../guides/features.md)
  are refused on executors that isolate from the host, so their workspace is
  always `bind`. `cloop feature pr` pushes with the lease's environment (through
  the proxy if the project holds a guarded grant, so only to `cloop/**`) and
  opens the pull request through the GitHub REST API directly, which the proxy
  does not carry.

[Secret file delivery](executors.md#secret-file-delivery) covers where the files
land and how each driver wipes them, and
[workspace provisioning](executors.md#workspace-provisioning) covers where each
driver's fetch runs.

---

## What the sandbox holds

### On the workspace path

Nothing on disk. The session credential goes only to the git child process
that fetches, as an origin-scoped `http.<https://proxy/>.extraHeader` set through
git's `GIT_CONFIG_COUNT` environment protocol, together with
`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, an empty
`credential.helper` and `http.followRedirects=false`. The checkout's own
`.git/config` records the remote (the proxy's URL) and no credential. The
[four absences](../security/model.md#the-four-absences) still apply; the
difference is that what they keep out of view is now good for one repository
for one TTL.

### On the lease path

Three files in the lease directory:

```
git-proxy-credential   0600   username=<session id>
                              password=<session token>
git-credential-cloop   0700   the helper below
gitconfig              0600   the configuration below; GIT_CONFIG_GLOBAL names it
```

The gitconfig, as rendered for a proxy advertised at
`https://hub.internal:8443`:

```ini
# Generated by cloop secretbroker for the lifetime of one lease.
# GitHub is reached through cloop's git proxy, which holds the
# credential and enforces this grant's repository allowlist and
# ref policy. The token itself is not present in this sandbox.
[credential]
	useHttpPath = true
	helper = !"$CLOOP_LEASE_DIR/git-credential-cloop"
[url "https://hub.internal:8443/"]
	insteadOf = https://github.com/
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
```

And the helper:

```sh
#!/bin/sh
# Generated by cloop secretbroker. Releases a cloop git proxy session
# credential for the proxy host only. Do not edit.
set -u
[ "${1:-}" = get ] || exit 0
dir=$(dirname "$0")
proto=; host=
while IFS='=' read -r key value; do
  case "$key" in
    protocol) proto=$value ;;
    host) host=$value ;;
  esac
done
[ "$proto" = https ] || exit 0
[ "$host" = hub.internal:8443 ] || exit 0
[ -r "$dir/git-proxy-credential" ] || exit 0
cat "$dir/git-proxy-credential"
```

Three details in these files:

- **The ssh forms are rewritten too.** A sandbox has no ssh key, so a
  `git@github.com:acme/tool` remote (from a submodule, say) would fail.
  Rewritten, it becomes a fetch the grant may authorise.
- **The helper answers for the proxy's host and nothing else.** The session
  token is useless anywhere else, so this is about the rewrite. If a workload
  points its remote back at GitHub, a helper that answered for `github.com`
  would give it a credential that fails there with an obscure error. Instead
  the workload gets git's own "could not read Username", which points at the
  cause.
- **The base URL is rebuilt, not copied.** It is parsed and rebuilt from its
  scheme and host, and the host is checked against a narrow character set,
  because it is written inside a quoted gitconfig section header and into a
  shell script.

The environment variables set beside the files (none of them a credential):

| Variable | Value |
| --- | --- |
| `GIT_CONFIG_GLOBAL` | `<lease dir>/gitconfig` |
| `CLOOP_LEASE_DIR` | the lease directory, which the gitconfig finds the helper through |
| `CLOOP_GIT_PROXY_URL` | the proxy's base, `https://hub.internal:8443` |
| `CLOOP_GIT_PROXY_SESSION` | the session id, which the hub uses to find the session to close when the lease is released. It is the non-secret half of the credential and appears on every audit row |
| `CLOOP_GIT_PROXY_MODE` | `read-only` or `read-write` |
| `CLOOP_GITHUB_REPO_ALLOWLIST` | the grant's repositories, e.g. `acme/*` |
| `CLOOP_GITHUB_PERMISSIONS` | the grant's permissions, when it lists any |
| `CLOOP_GIT_PUSH_REFS` | read-write only: the hub's ceiling, e.g. `refs/heads/cloop/**` |
| `CLOOP_GITHUB_PUSH_BRANCHES` | read-write only, when the grant lists branches |

There is no `github-token` file, no `GITHUB_TOKEN` or `GH_TOKEN` (even for a
`*` allowlist, where an unguarded delivery exports them), and no
`CLOOP_GITHUB_TOKEN_EXPIRES_AT`, because there is no GitHub token in the sandbox
to expire. Plan for one consequence: `gh`, and anything else that uses GitHub's
REST or GraphQL API, has nothing to authenticate with. The proxy carries git's
smart-HTTP protocol and nothing else.

---

## Which credential reaches the sandbox

What a GitHub grant turns into depends on whether the proxy is running, on the
grant's kind, and on whether the grant restricts branches.

**The lease path** (the workload's own git):

| This hub | `github_pat` | `github_app` | Grant with a branch list |
| --- | --- | --- | --- |
| **Runs the proxy** | a scoped session; read-only unless the grant has `contents:write` | an installation token minted for the lease and held by the hub; a scoped session in the sandbox | enforced by the proxy, outside the sandbox |
| **Has a valid `enabled: true` section, but no proxy running** | not delivered (`ErrGuardUnavailable`); the rest of the lease still is, and the run starts without GitHub access | the same, and the minted token is revoked at GitHub | not delivered |
| **Has no proxy** | the PAT itself in `github-token`, released by an in-sandbox helper for allowlisted repositories only. The workload can also use it against GitHub's REST API, and for any push the PAT allows | the installation token itself in `github-token`, which GitHub has already scoped to the grant | `github_app`: minted read-only, with the reason in `CLOOP_GITHUB_WRITE_WITHHELD`. `github_pat`: not delivered (`ErrBranchesUnenforced`) |

**The workspace path** (cloop's own fetch):

| This hub | Any GitHub grant | Grant with a branch list |
| --- | --- | --- |
| **Runs the proxy** | a pinned session for the one repository | kept writable, because the proxy holds the credential (`GitHubProxied`) |
| **Has a valid `enabled: true` section, but no proxy running** | the dispatch is refused with `ErrWorkspaceUnavailable`, which names the section as the cause instead of a missing grant | the same |
| **Has no proxy** | the forge token itself, on one git child | `github_app`: minted read-only, so the fetch works and a push would not. `github_pat`: refused (`ErrBranchesUnenforced`) |

In code, the lease path is decided by `githubMaterial` and `githubAppMaterial`
in `pkg/secretbroker/material.go`, and the workspace path by
`gitproxycreds.Source` and `unavailableWorkspaceSource`. `attachGitGuard`
attaches `gitGuard` to a broker on a hub with a running proxy, an
`UnavailableGitGuard` on a hub whose configured proxy is not running, and
nothing on a hub with no proxy. `branchEnforcement` applies the same rule for
the dashboard, and `TestBranchEnforcementTellsTheTruthAboutThisHub` checks that
the two agree.

Note the word "valid" in those tables. A section with `enabled: true` that
cannot produce a usable proxy (it has neither `tls: auto` nor both `cert_file`
and `key_file`, or an unusable `listen_addr` or `advertise_url`) is switched off
when the configuration is loaded, with a `warning: config executors.git_proxy.…`
line. The hub then behaves as one with no proxy: credentials are delivered into
sandboxes. Only a section that loads cleanly and whose proxy then fails to
start fails closed. That includes `tls: auto` on a hub with no
`CLOOP_SECRET_KEY` to seal its CA under. See [how it fails](#how-it-fails).

To make the "Has no proxy" row rare, `cloop hub
bootstrap` turns the proxy on with `tls: auto`, which needs no certificate files
and no CA in any image. On a hub with `allow_host_process: false`,
`cloop hub doctor` names every GitHub grant delivered into sandboxes without a
proxy (`gitproxy.forge_credentials`).

The only combination with no boundary is a hub with no proxy and a grant with
no branch list. The credential is then in the sandbox, and a PAT's allowlist
limits only what git does; it does not stop a workload that reads the token
file. See [the helper's limit](../guides/secrets.md#the-helpers-limit-and-what-removes-it).

---

## The network between sandbox and proxy

### From the sandbox to the proxy

`listen_addr` is where the proxy binds. `advertise_url` becomes the sandbox's
remote, so it has to resolve and route from wherever git runs: the table
[above](#executor-by-executor) says where, and the
[table of forms](../git-interception-proxy.md#advertise_url-what-the-sandbox-can-reach)
turns that into URLs. cloop does not open the path for you: no firewall, egress
filter or `NetworkPolicy` that cloop renders allows the proxy's address by
itself. Each backend's network has to admit it:

| Sandbox network | What it takes |
| --- | --- |
| `network: none` (the `container` driver's default, and a virtual executor's with neither a firewall nor a `network`) | Nothing reaches the proxy. The lease path fails with `Could not resolve host` or a connect error. Give the executor a network or a firewall. |
| A bridge with no filter | The advertised host has to resolve and route from the container: `host.docker.internal` or `host.containers.internal` for a hub on the same machine, a routable address otherwise. |
| `egress_filter` with direct egress | Private address space is blocked unless listed, so the proxy's address needs an `allow_cidrs` entry, its port an `allow_ports` entry, and its name a resolver in `resolvers`. |
| `egress_filter` with `internal: true` | The sandbox's network has no route off the host, so the proxy must be advertised at an address on that network, as the [egress broker](../reference/configuration.md#scoped-network-egress) is, with a certificate that covers it. |
| A virtual executor's firewall | The same as direct egress: `allow_cidrs` with the hub's address, `allow_ports` with the proxy's port, and a resolver. The minimal one is `{"allow_cidrs": ["<hub-ip>/32"], "allow_ports": [<port>], "resolvers": ["1.1.1.1"]}`. Any firewall needs the device's agent to have the packet-filter grant, which the installer gives by default; `sudo cloop executor agent install --upgrade --packet-filter` adds it to a device installed without it. |
| Kubernetes, egress filter off | No `NetworkPolicy` is created; the Pod reaches whatever the cluster routes. |
| Kubernetes, egress filter on | Each Pod's policy admits only the configured ranges and ports and cluster DNS, with no peer for the proxy. Add the hub's address range and port. |
| A project whose `.cloop/sandbox.yaml` sets `capabilities.egress: public` | Every private address is dropped for that project's sandboxes, on the container driver and on Kubernetes, including a proxy on a private address, a `Service` IP or the host bridge. Advertise the proxy at a public address, or remove that setting for the project. |

`cloop hub doctor`'s `gitproxy.advertise_reachable` check dials the advertised
address from the hub, with a timeout of a few seconds. That shows something is
listening, but says nothing about the sandbox's route to it. The only check of
the sandbox's side is a clone from inside a sandbox.

The proxy's certificate is validated by the sandbox's git, not by the hub's
HTTP client. Under `tls: auto`, git validates it against the hub's CA, which
every dispatch carries and every driver installs for the proxy's URL only, so
neither the device host nor any image needs to trust anything in advance.
Otherwise, the workspace fetch uses the trust store of the machine it runs on
(the device host, or the harness image in a Pod's init container) plus the
transport variables `pkg/executor/gitprovision` forwards: `GIT_SSL_CAINFO`,
`GIT_SSL_CAPATH`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, and the `HTTPS_PROXY` /
`ALL_PROXY` / `NO_PROXY` family. The lease path uses the sandbox image's trust
store. See
[the certificate the sandbox has to trust](../git-interception-proxy.md#the-certificate-the-sandbox-has-to-trust).

### From the proxy to the forge

The connection from the proxy to the forge is the hub's own outbound traffic,
and a request cannot steer it:

- **The host comes from the session.** A pinned session forwards to the
  workspace's own origin, which may be any https forge. A scoped session
  forwards only to `https://github.com`, a constant in `pkg/ui/gitguard.go` and
  not a setting, because no configuration value should be able to send a user's
  GitHub token to another host.
- **Redirects are refused**, so a forge cannot move the credential to a host the
  session was never scoped to.
- **The hub's own environment applies.** The hub builds the upstream transport
  with no options, so it honours `HTTPS_PROXY` and `NO_PROXY` from the hub's
  environment (a hub behind a corporate proxy reaches the forge the way its
  other traffic does). It verifies the forge against the hub host's system
  roots, which Go extends with `SSL_CERT_FILE` and `SSL_CERT_DIR`; use those to
  trust a forge behind a private CA. `gitproxy.Options.Transport` is for code
  that embeds the package and is not a hub setting, and there is no option to
  switch verification off.
- **Timeouts** are 15 s to connect and 60 s for the forge to start replying. There
  is no overall limit, because cloning a large repository can take a long time.

---

## How long a session lives

The two paths end their sessions on different events.

**A workspace session lives as long as its run needs it.** The fetch happens at
the start of a run, and a push write-back (if asked for) at the end. So the
session is minted for `session_minutes` (60 by default, 720 at most) and renewed
by another period whenever five minutes or less are left
(`gitproxy.RenewMargin`), for as long as the driver holds the credential.
`gitproxycreds.Source` runs the renewer and stops it when the driver releases
the credential, once the run is done with it: after the fetch for a run that
pushes nothing back, or, for one that does, once the workload has ended and its
write-back has run or been abandoned. (The remote driver parks the release on
the handle; the Kubernetes driver keeps it with the workspace Secret.) The
release closes the session, used or not, with the reason *"the run is done with
its workspace credential"*, or *"workspace credential released unused"* if
nothing authenticated with it. Each renewal moves the recorded `expires_at` and
`renewed_at` and writes a `gitproxy.session_renewed` row. The sandbox gets no
deadline (the credential's `ExpiresAt` is zero), because the device refuses to
push past a deadline it holds, and one handed over at dispatch would be stale by
the time a long run writes back.

A hub shutdown suspends a recorded session, leaving its record open for the
process that adopts its run, and closes a session with no record with the
reason *"the hub is shutting down"*. The adopting process restores the session
with its renewed deadline, bounded by `session_minutes` from its last renewal
(not from when it was issued). It renews it from the keepalive of the workspace
lease it took over, asking the executor whether the workload still runs only
when a renewal is due, until the workload ends; then the lease is released and
the session closed with it. The reaper drops a lapsed session within five
minutes. The lease behind a session is kept alive while the session lives, and
listed among the hub's leases, where revoking it closes the session. It is
released when the session ends, and a `github_app` token with it.

**A lease session ends with the lease that minted it**, on whichever of these
comes first:

| Event | Where |
| --- | --- |
| The workload reaches a terminal state and its lease is wiped | `wipeLeaseOnExit`, `pkg/ui/executor.go` |
| The dispatch fails after the lease was taken | every early return in `startWorkloadAs` |
| An operator revokes the lease, or cordons, drains or revokes the edge device holding it, from the dashboard or the CLI | `revokeLeaseEverywhere`, `pkg/ui/secrets_revoke.go`; the CLI's announcement in `pkg/ui/executor_revocation.go` |
| The identity whose credential it is gets offboarded | the offboarding lease release, `pkg/ui/offboard_api.go` |
| The lease lapses: the lease janitor sweeps expired leases every minute, but a live run's lease is extended before it can lapse | `sweepExpiredLeases`, `pkg/ui/secrets_revoke.go` |
| The session's own TTL runs out | the proxy refuses it at authentication |

Each of the first five runs `secretLease.Close`, which calls
`closeGuardedSessions`. That closes every `CLOOP_GIT_PROXY_SESSION` the lease's
materials carried, and each `gitproxy.session_closed` row records the reason
*"lease released"* with the session's push, fetch and denial counts. Wiping the
lease directory removes the token from the sandbox, but without closing the
session, a workload that copied the token first would keep PAT-backed access to
the whole allowlist until the TTL.

A run's lease is issued at dispatch for at most
`secretbroker.DefaultMaxLeaseTTL` (15 minutes) and kept alive while the run
lasts. Every lease the hub issues has a keepalive (`secretLease.keepAlive`,
`pkg/ui/secrets.go`) that checks once a minute and, when the deadline is within
five minutes, extends the lease in place with `Broker.Extend`: same lease, same
material, and a new deadline one lease period out. Extending re-reads every
grant the lease holds, so a grant that expired since dispatch refuses the
extension and the lease lapses at its current deadline. A revoked grant takes
effect at once: the revocation reaches every lease carrying the grant (the
sessions minted for it are closed, its App tokens destroyed and its files taken
back), and the lease goes on extending on its other grants. The janitor finds
any unannounced revocation within a minute (see
[Revoking a grant](../security/model.md#revoking-a-grant)). A workload the
executor reports finished is not extended, and the keepalive stops when its
holder closes the lease. Each extension is a `secret.renew` row reading
*"extended in place while its run is live"*. The keepalive moves with the run: a
lease is recorded in `secret_leases` under the hub process holding it, and if
that process stops mid-run, the process that adopts the run takes the lease over
and keeps it alive, writing a `secret.renew` row that reads *"taken over by the
hub process that adopted its run"*.

A push refused because its session was closed shows a `gitproxy.rejected` row
whose detail is only `gitproxy: unauthenticated`. Closing a session removes it
from the registry, so a later request presenting it looks the same as one
presenting a token that never existed. The reason is on the
`gitproxy.session_closed` row before it.

A lease session is still bounded by its own TTL, `session_minutes`, counted
from dispatch: the keepalive extends the lease but not the session. (A workspace
session, by contrast,
[is renewed while its run lives](../git-interception-proxy.md#a-workspace-session-lives-as-long-as-its-run).)
Set `session_minutes` to cover the longest run you expect the hub to complete.

### The upstream credential renews itself

Extending a lease changes nothing at GitHub, and the installation token a
session presents upstream for a `github_app` grant is valid for an hour. So a
session minted for one gets the broker's refresher with it
(`GitGuardRequest.Refresh`, passed on as `MintRequest.Refresh`) and keeps the
token in generations (`pkg/gitproxy/refresh.go`):

```
request ─▶ credentialFor(session)
             ├─ more than 10 min left ─▶ present the current generation
             └─ 10 min or less ─▶ one refresh at a time (the others wait for it)
                  └─ Broker.refreshSlot ─▶ grant re-read ─▶ mint at the original scope
                       ├─ ok ─▶ new generation; the old one is retired — destroyed at
                       │        GitHub — when the last request presenting it finishes
                       ├─ refused for good ─▶ Registry.Close("upstream credential will
                       │        not be renewed: …"), tokens destroyed, 401
                       └─ may pass ─▶ keep presenting the held token while it works,
                                retry after a minute; once it has lapsed, 502 with why
```

The refresh asks GitHub for what the first mint asked for (the same
installation, the same repositories by ID, the same permissions) and refuses an
answer wider than the first token's, so a session never comes back with more
than it was minted with. It re-reads the grant first. If the grant was revoked
or expired, issued to someone else, or its secret is gone or names another
installation, the session ends as on a revocation. A request waiting on a
refresh is bounded by its client, and the refresh itself by 45 seconds,
independent of the request that started it. When the credential is an App
token, the workspace path's pinned sessions renew the same way, through
`gitcreds.BrokerSource.RefreshWorkspaceCredential` on the inner lease.

Each new token is an allowed `secret.renew` row naming the session, and each
refusal a denied one beside the session's `gitproxy.session_closed` row.
Destroying the superseded token writes a `github_app.token_destroy` row.

Without the proxy, the lease's keepalive refreshes the same broker slot, and the
new token goes to the executor holding the file (see
[keeping the token past GitHub's hour](../guides/secrets.md#keeping-the-token-past-githubs-hour)).

### A hub restarted mid-run

A device keeps running its task while its hub restarts (:8888 restarts nightly,
and sometimes off schedule). The process that adopts the run takes over its
lease and restores the lease sessions that lease fed, so the workload's next
fetch or push is served as if nothing had happened.

**Recorded.** A lease-path session is minted `Durable`, and the registry's store
(`pkg/sessionrecord`) writes a `proxy_sessions` row before the session is handed
out: the session id, the SHA-256 of its token, the lease and grant it stands on,
the run, project, executor and actor, the scope (the repository allowlist, the
forge host and the ref policy), the deadline, and the hub process serving it.
The row never holds the token, or the PAT or App token presented upstream;
`tests/security/sessionrecords_test.go` scans the table for them after a
realistic run. The App token behind a session has its own row in
`app_token_slots`: the installation, the repository ids, the permissions asked
for and the ones GitHub granted. The session's end is written to its row as it
happens, fenced on the holder.

**Stopping.** A hub that stops gracefully suspends a recorded session instead of
closing it: it stops serving the session and destroys the App token it
presented, but writes no close row and leaves the record open. A SIGKILL leaves
the same state, except that the token is not destroyed and lapses after
GitHub's hour.

**Restored.** When the agent reconnects and the new process adopts the run
(`takeOverRunLeases`, `pkg/ui/session_restore.go`), each open session the run's
lease feeds is:

1. retired with a `gitproxy.session_closed` row if its TTL ran out in the
   meantime;
2. taken over by a conditional write on its holder, so of two processes
   adopting the run, only one gets it;
3. held to what its grant and this hub's proxy policy allow now: every recorded
   repository pattern must be in the grant's allowlist, every ref pattern in the
   hub's, and every write the session may make allowed by both. A scope that
   cannot be shown to be within these bounds is refused, never widened;
4. held to where this hub mints sessions now and for how long, whatever the
   record says: its upstream must be the forge this hub's proxy fronts for the
   grant's host (`https://github.com`, or `https://<host>` for a GitHub
   Enterprise Server; only tests swap in a local forge, through the
   `github_upstream` override, which no configuration sets), and its deadline
   is clamped to the session TTL from when it was issued or, for a workspace
   session, last renewed. A record comes from a database, so nothing in it
   decides where a credential is presented;
5. given an upstream credential derived again from the lease: a PAT opened from
   the grant's secret, or an App installation token minted at once at the slot's
   recorded scope (the installation and GitHub host the sealed secret names,
   only the recorded repository ids the grant's allowlist still admits in the
   installation, and the recorded permissions, never wider). Its refresh then
   continues from the session's request path;
6. put back into the registry under its id and token hash, with its policy and
   deadline. A [`gitproxy.session_restored`](../reference/audit-events.md#gitproxy)
   row names the process that held it.

If a grant expired while no process held the lease, the lease itself is
refused: the lease path closes its sessions with a reason and scrubs the device.
A revoked grant refuses only its own share when the lease carries other grants:
the adopting process takes that grant back from the workload, does not restore
its sessions, and keeps the rest. A temporary failure (the database busy, or
GitHub unreachable for the new token) leaves the session held by the new process
but not restored, and the lease's keepalive tries again every minute, as does
the next request presenting it. A retry reads the record again first. A session
another process has taken over since is left to it, and a lease another process
has taken is handed over: its sessions are suspended and its App tokens
destroyed.

**Handing over a live run.** When a run moves between two live members, the old
member learns of it at once and waits up to two minutes for the new one to take
the lease. It then suspends the sessions the lease fed and releases its claim on
them, so a request reaching any member is forwarded to the member that restored
them.

**Before adoption.** The new process starts before the device's agent has
reconnected, and the reconnect is what adopts the run, so a request in that gap
presents a session no process serves. The session is not restored on demand:
restored by a process that does not hold its lease, it would outlive the
lease's revocation and release. Instead, a request whose credential hashes to
an open, unexpired record whose holder is not a live hub process waits up to 60
seconds for the run to be adopted (by then a device's agent is reconnecting on
a backoff of tens of seconds). It is then served here or forwarded to the
member that restored the session; otherwise it gets a 401, as before. A wrong
token is refused at once. Requests presenting one session share one wait, at
most 64 sessions are waited for at a time, and a proxy that stops ends every
wait. To git, a restart looks like a slow response instead of a failure.

A member that was killed still counts as alive until its heartbeat goes stale:
until the next membership refresh on its own host, where its process is
checked, and for its whole TTL from another host. A request for one of its
sessions is forwarded to it in that time. When nothing accepts the connection,
the request waits as above instead of failing with a 502, and the member is
passed over for the TTL.

The leader's janitor retires the records of closed sessions; of open ones whose
holder is gone, once the session or its lease lapses; and of any open one well
past its TTL, whoever holds it.

**A workspace's pinned session**, which cloop's own provisioning fetch and a
write-back push use, is restored the same way, although it stands on a lease of
its own instead of the run's:

- The workspace lease is recorded in `secret_leases` like any lease. The
  dispatching process keeps it alive (it is listed among the hub's leases and
  can be revoked there) for as long as the session standing on it lives, and
  releases it when the session ends. The session is minted `Durable` when its
  lease is recorded, so it has a `proxy_sessions` row (token hash only). Its
  GitHub App token's slot is recorded as held by the proxy, which renews it.
- A driver that keeps the credential after dispatch (a device whose run pushes
  its work back, with `executors.write_back: push`) names both in the run's
  owner row, as `workspace: {lease, session}` beside the run's own `leases`.
- The process that adopts the run takes over the workspace lease
  (`takeOverWorkspaceLease`, `pkg/ui/workspace_lease.go`) and restores the
  session with the steps above: a conditional write on the holder, the
  repository and policy checked against what the grant (with its branches) and
  the hub's proxy policy allow now, the deadline clamped, and a GitHub App token
  minted at once at the slot's recorded scope. The upstream is taken from the
  project's own git origin as `applyWorkspace` derives it now, so a record
  naming another repository or host is refused, and nothing in it decides where
  the credential goes. The adopting process ends both with the workload, as it
  does the run's lease.

A write-back push that arrives after the restart but before the device's agent
has reconnected waits for the adoption, like any request for a recorded
session. A device run that pushes no work back releases its workspace
credential once it has been delivered. Its session, used once by the
provisioning fetch, lives out its TTL on the process that minted it and is not
named for adoption, since nothing presents it again. For Kubernetes, see
[limits that remain](#limits-that-remain).

---

## How it fails

| What happened | What the hub says | Workspace path | Lease path |
| --- | --- | --- | --- |
| No section, or `enabled: false` | nothing | the forge credential goes to the git child that fetches | the token goes into the sandbox, limited by the helper |
| `enabled: true`, but neither `tls: auto` nor a TLS pair, or an unusable `listen_addr` / `advertise_url` | `warning: config executors.git_proxy.…` at load; the section is switched off | as if there were no section | as if there were no section |
| `tls: auto` on a hub with no `CLOOP_SECRET_KEY` | `ui: git interception proxy NOT started: git proxy TLS (tls: auto): hubca: the hub's certificate authority needs CLOOP_SECRET_KEY …` | refused with `ErrWorkspaceUnavailable` | GitHub material not delivered (`ErrGuardUnavailable`) |
| `tls: auto`, a device whose agent speaks a protocol older than v21 | the dispatch is refused, naming the device's protocol, v21, and the upgrade path | refused | refused: the workload would reach the proxy without its CA, and the forge credential is never the fallback |
| `tls: auto`, a leaf the leader failed to renew | `ui: the git proxy's certificate could not be renewed: …`; `cloop hub doctor` fails `gitproxy.tls` with less than a day left | no effect until it lapses; then the sandbox's git refuses it | the same |
| A valid section whose proxy did not start (port taken, certificate unreadable) | `ui: git interception proxy NOT started: …` | refused with `ErrWorkspaceUnavailable`; on Kubernetes every git workspace, public ones included | GitHub material not delivered (`ErrGuardUnavailable`); the run starts without it; App tokens revoked |
| One executor could not be wrapped | `ui: executor <id> is NOT routed through the git proxy: …` | that executor's workspaces refused | unaffected |
| The audit database would not open | `ui: git proxy decisions will go to stderr, not the audit trail: …` | still enforced; the record goes to stderr, prefixed `git-proxy:` | the same |
| A session could not be minted at dispatch | the dispatch error names the repository | dispatch fails, inner lease released | that GitHub material fails, as above |
| The sandbox cannot reach `advertise_url` | git: `Could not resolve host`, `Failed to connect`, or a timeout behind a firewall that drops packets | the fetch fails | the workload's git fails |
| The sandbox does not trust the certificate (an operator's own pair whose CA is in no image, or an `advertise_url` the hub's leaf does not name) | git: `SSL certificate problem` | the fetch fails | the workload's git fails |
| The session lapsed or was closed | git: an authentication failure (HTTP 401); a `gitproxy.rejected` row, naming the expiry if the reaper has not swept the session yet and only `unauthenticated` once it is gone | a late push fails | late git fails (see [how long a session lives](#how-long-a-session-lives)) |
| An App token's renewal was refused: grant revoked or expired, installation suspended, repository removed | git: HTTP 401 on the request that found the renewal due; the session's `gitproxy.session_closed` row says *upstream credential will not be renewed* and why; a denied `secret.renew` | that session's git ends | that session's git ends; the grant's tokens are destroyed |
| An App token's renewal failed for a reason that may pass (GitHub unreachable, rate limiting) | a denied `secret.renew` saying it will retry | git carries on with the held token while it is valid; after it expires, HTTP 502 with the reason, until a retry succeeds | the same |
| A repository outside the session's scope | HTTP 403, `session is scoped to …`; a `gitproxy.rejected` row | — | refused |
| A ref outside the policy | `! [remote rejected] … (…)`; a `gitproxy.push_denied` row | refused | refused |
| A push carrying a credential the run was given | `remote:` lines naming each object, its path and commit, and the grant and secret; `! [remote rejected] … (carries a credential this run was given: …)`; a `gitproxy.push_secret_refused` row; a `git_push_refused` row in the run's history and a line in the task's details | refused, no ref moves | refused, no ref moves |
| A push past a `push_scan_*` limit, or one the proxy cannot read | `remote:` naming the limit and its setting, or what could not be read; a `gitproxy.push_denied` row with `scan` set; the same history row | refused | refused |
| The hub restarted mid-run | `ui: restored git session … of lease …, held until then by …` when the run is adopted; a `gitproxy.session_restored` row | restored with the run; a fetch or push made before the run was adopted waits up to 60 s for it | restored; a request made before the run was adopted waits up to 60 s for it |
| A restored session was refused: its grant was revoked or expired while the hub was down, its recorded scope is wider than the grant or the proxy's policy now allows, its upstream is not the forge this hub's proxy fronts, or this process runs no proxy | a `gitproxy.session_closed` row whose detail begins *not restored by the hub process that adopted its run* | — | git: HTTP 401 |

Two properties of that table are easy to miss. First, a proxy the operator
asked for and did not get fails closed: the dashboard still starts, but git
workspaces and GitHub leases stop. Second, whether a proxy was asked for is
decided from the configuration after load-time repair. A section with
`enabled: true` and missing TLS material is switched off with a warning, and the
hub then hands out credentials as if there were no proxy. After enabling the
section, check the startup log for `ui: git interception proxy on …`. If that
line is missing, the proxy is off.

---

## Observing it

### The audit trail

Every decision the proxy makes is a row in `audit_events`, with `entity_type`
`gitproxy` and the session id as the entity:
[`gitproxy.session_minted`](../reference/audit-events.md#gitproxy),
[`gitproxy.fetch`](../reference/audit-events.md#gitproxy),
[`gitproxy.push_allowed`](../reference/audit-events.md#gitproxy),
[`gitproxy.push_denied`](../reference/audit-events.md#gitproxy),
[`gitproxy.push_secret_refused`](../reference/audit-events.md#gitproxy),
[`gitproxy.rejected`](../reference/audit-events.md#gitproxy),
[`gitproxy.session_restored`](../reference/audit-events.md#gitproxy) and
[`gitproxy.session_closed`](../reference/audit-events.md#gitproxy). The payload
holds the session, the repository the request addressed, the project and task
ids, the refs and the reason. It never holds a credential, because
`gitproxy.Event` has no field that could hold one. A push the scan refused also
carries the run's id, its `findings` (object, path, commit, grant, secret,
field), and its refs with any of the run's values removed. A request that
presented no credential at all is counted instead of audited; see
[audit events](../git-interception-proxy.md#audit-events).

A push the scan refused is also recorded where the people running the project
look: a `git_push_refused` row in the run's history (the project's event
journal), linked to the running task if only one was running, and a line in
that task's details. The line is added to the details view and not written into
the stored task, whose annotations only the run writes.

Under `tls: auto` the certificates are audited too:
[`hub_ca.minted`](../reference/audit-events.md#hub_ca) when a hub process mints
the control plane's CA, with its SHA-256 for comparison with the PEM a sandbox
was given, and [`hub_ca.leaf_issued`](../reference/audit-events.md#hub_ca) for
every leaf, naming the monitor, the names it carries and the serial it
replaced. A second `hub_ca.minted` for one control plane means its `hub_tls`
table was lost or restored without the CA, and sandboxes holding the first CA
will refuse the next leaf.

Three joins answer most questions:

- **Session → everything it did.** The session id is on its mint row, every
  request row and its close row (`cloop audit-log list --entity gitproxy`).
- **Lease → session.** A guarded lease's material names the session in
  `CLOOP_GIT_PROXY_SESSION`, and the
  [`secret.lease`](../reference/audit-events.md#secret) row written for each
  grant it delivered has, as its `reason`, a summary of what the proxy will
  enforce: `github read-write via git proxy, repos acme/*, refs
  refs/heads/cloop/**` for a PAT — with `narrowed to …` appended when the grant
  lists branches, or `github app installation … token for … (proxy-guarded,
  read-write), expires …` for an App. The Secrets panel's live-lease table shows
  the same summary.
- **Workspace fetch → grant.** The
  [`workspace.provision_start`](../reference/audit-events.md#workspace) and
  `workspace.provision_end` rows name the grant and lease that authorised the
  fetch, and the real repository instead of the proxy's URL.

### Metrics

The hub's `/metrics` has `cloop_gitproxy_pushes_total{result}`,
`cloop_gitproxy_push_denials_total{reason}` and
`cloop_gitproxy_anonymous_requests_total`, and for the push scan
`cloop_gitproxy_push_scans_total{result}`,
`cloop_gitproxy_push_scanned_bytes_total` and the
`cloop_gitproxy_push_scan_seconds` histogram. They count pushes only. A fetch,
a session, and a refusal before any ref was decided (a repository outside
scope, or a session that cannot push asking for the receive-pack advertisement)
appear in the audit trail and in no counter. See
[metrics](../operations/metrics.md#git-interception-proxy).

### `cloop hub doctor`

The `gitproxy` checks read the same configuration the hub does:
`gitproxy.enabled`, `gitproxy.tls`, `gitproxy.advertise_url`,
`gitproxy.advertise_reachable` (the bounded dial from the hub),
`gitproxy.allowed_refs` (patterns outside `refs/heads/cloop/`),
`gitproxy.allow_delete`, and, with the proxy off, `gitproxy.branch_grants`,
which counts the grants whose branch list this hub therefore delivers read-only
or not at all. On a hub with `allow_host_process: false`,
`gitproxy.forge_credentials` names every GitHub grant delivered into sandboxes
as the credential itself. Under `tls: auto`, `gitproxy.tls` reads the CA and
the leaf from `hub_tls`. It passes before the hub has first started, fails
without `CLOOP_SECRET_KEY`, and fails a leaf that does not chain to the hub CA,
has less than a day left (the leader renews with two), or does not name the
host of `advertise_url`. `hubca.expiry` warns a year before the CA itself
expires. `--smoke` brokers a real lease from a process that has no proxy, so on
a hub with the section enabled it attaches an `UnavailableGitGuard` and refuses
GitHub material instead of writing a token into its smoke sandbox.

### The dashboard

A project's **Repository access** panel reads `git_proxy` from
`GET /api/projects/{idx}/repositories` (whether a proxy is running, whether one
is required, and the hub's push ceiling) and shows under the branch field what
a list will amount to on this hub. In the Secrets panel, a grant that lists
branches has `branch_enforcement` (`proxy`, `unavailable`, `read_only` or
`not_delivered`), and a `github_pat` or `kubeconfig` grant has `enforcement`
(`proxy` or `unguarded`). The second is coarser: a hub whose configured proxy is
down reports `unguarded` there, although its GitHub leases then fail instead of
delivering. Neither view shows the listen address, certificate path or session
count: none of them helps anyone choose a branch, and all of them would help an
attacker map the system.

---

## How it is tested

| Layer | What it proves | Where |
| --- | --- | --- |
| Policy and sessions | ref matching against the documented table, narrowing, TTLs, one error for every authentication failure | `pkg/gitproxy` unit tests |
| The proxy against a real git | `git` → proxy → `git-http-backend` behind TLS → a bare repository that demands the credential, so "the ref did not move" means the proxy declined | `pkg/gitproxy` `*_e2e_test.go` |
| The workspace decorator | the PAT reaches no part of what a driver is handed, the session's expiry is the one the sandbox gets, minting fails closed | `pkg/executor/gitproxycreds` |
| The hub wiring | TLS on the listener, fail-closed when required and absent, both halves of a session narrowed by the grant's branches | `pkg/ui` `gitproxy_test.go`, `gitguard_test.go` |
| The lease delivery with real git | the rewrite, the helper's host check, no token on disk | `pkg/secretbroker` `guardedintegration_test.go` |
| Conformance | a guarded PAT never reaches either delivery shape; a broken guard never delivers the token | `tests/security/gitguard_test.go` |
| The push scan | packs written by `git pack-objects` (full and thin, OFS and REF deltas, SHA-1 and SHA-256) scanned for a value in a blob, a commit message, an annotated tag, a delta's inserts, a ref name or a push option, in every encoding; the checksum held until the verdict; malformed packs, limits and the copy/insert residual pinned; a fuzz target checking that the reader never hands on a pack it refused; real `git` pushes refused with no ref moved and no object left on the forge, and a clean one forwarded byte for byte; the hub's values per run, project tightening, adoption, the journal and the task's details; and every credential kind a real lease delivers refused, encoded or not, before the forge holds a complete pack | `pkg/gitproxy` `packscan_test.go`, `pushscan_e2e_test.go`, `FuzzPackScan`; `pkg/secretbroker` `credentialvalues_test.go`; `pkg/ui` `gitproxy_pushscan_test.go`; `tests/security/pushscan_test.go` |
| Workspace credentials in a Pod | the session id reaches the init container through the run's Secret, the helper is projected executable, and the lease behind the token lives as long as that Secret | `pkg/executor/kubernetes` `workspace_test.go`, `secretfiles_test.go` |
| The proxy's CA in a Pod | the bundle is mounted in both containers and trusted for the proxy's URL only, joining any `GIT_CONFIG_COUNT` block already there; a real git fetch through a closed environment trusts a CA scoped to its remote and not one scoped elsewhere | `pkg/executor/kubernetes` `cabundle_test.go`; `pkg/executor/gitprovision` `TestProvisionTrustsACertificateScopedToTheRemote` |
| The hub's own CA (`tls: auto`) | minted once by racing members, its key sealed and bound to its row, rewrapped by key rotation and counted by retirement; leaves for the advertised names, renewed by the leader with overlap and adopted by followers, a TLS connection open across a renewal kept; the hub serving it to both monitors and shipping it to each dispatch for the proxy's URL only; a Pod taking it from its lease Secret; an older agent refused with the upgrade named | `pkg/hubca`; `pkg/ui` `hubtls_test.go`; `pkg/executor/kubernetes` `hubca_test.go`; `pkg/executor/remote` `gitca_test.go`; `pkg/executor/localprocess` `gitca_test.go` |
| `tls: auto` in a real sandbox | an image carrying no CA clones and pushes through an auto-TLS proxy, and the same git refuses a second https server whose leaf the same CA signed: in a container (`CLOOP_GITCA_CONTAINER_E2E=1`, a CI step), and on a device through a real hub and agent, whose provisioning fetch trusts the CA from the start frame | `pkg/executor/container` `TestContainerGitTrustsTheHubCAForTheProxyOnly`; `pkg/executor/remote` `TestLoopbackDeviceTrustsTheHubCAForTheProxyOnly` |
| A leaf rotation mid-run | a real git clones through an auto-TLS proxy and pushes on a new connection after the leader renewed the leaf. It pushes again after a second hub process took over the same address with an empty registry: that process adopted the stored leaf instead of issuing its own, and restored the durable session from its record | `pkg/hubca` `TestAGitSessionOutlivesARotationAndItsHubProcess` |
| A rotation of the hub CA | a real git dispatched after a stage (handed both CAs, and recording which on its executor session) clones and pushes through the auto-TLS proxy before the activation, after the leader reissued the leaf from the new CA, and after the old CA was retired. A git dispatched before the stage holds the activation back by name, and stops verifying the proxy once the activation is forced; an emergency rotation ends its proxy session | `pkg/ui` `hubca_rotation_e2e_test.go`; `pkg/hubca` `rotate_test.go` |
| Bootstrap and doctor | `cloop hub bootstrap` turns both monitors on with `tls: auto` (a golden file); `cloop hub doctor --smoke` passes on the hub it writes; the doctor's `tls: auto`, near-expiry, wrong-name and forge-credential findings; on a bootstrapped hub with a real container, the flagship circuit finds that the PAT stayed on the hub and that the sandbox's git trusts the hub CA at the proxy's URL and not at github.com's | `cmd` `hub_bootstrap_monitors_test.go`; `pkg/hubdoctor` `monitortls_test.go`; `tests/flagship` |
| A Pod on a real cluster | on every CI run, the Helm chart's hub on kind: a workload Pod provisioned through a pinned session, the lease's helper run at 0550, a clone and pushes through the proxy with the grant's repository and branch limits enforced and audited, no token in the Pod, and the run's objects gone afterwards | [`tests/kube`](../../tests/kube/README.md) |
| Session and lease lifetimes | a pinned session releases its lease once, when it ends; an unused one is closed on release; a lease is extended only while its grants hold and its run is live | `pkg/gitproxy` `session_test.go`, `pkg/executor/gitproxycreds`, `pkg/secretbroker` `extend_test.go`, `pkg/ui` `secrets_keepalive_test.go` |
| Live GitHub, opt-in | a grant assigned through the panel's endpoint pushes through the proxy to a real repository: refused outside its branches, landed inside them, with no token in the sandbox | `TestLiveBranchRestrictionThroughTheGitProxy` in `pkg/ui` |
| An App token past its hour | the clocks of a fake GitHub App API and of the broker are driven past the first token's expiry, against a forge that refuses expired tokens: a real git fetches and pushes through the proxy after it, at the first token's scope; a session that cannot renew is refused by the same forge; a revoked grant closes the session and mints nothing | `pkg/gitproxy` `refresh_e2e_test.go`, `refresh_test.go`; the hub's own adapter and lease files in `pkg/ui` `secrets_refresh_test.go`; the broker's rules in `pkg/secretbroker` `apprefresh_test.go` |
| A hub restarted mid-run | a session recorded without its token and restored by a second registry under the same id and token hash, its policy intact, with real git pushing through it; the restore refusing what a mint would; a graceful stop suspending instead of closing; the hub's restore at adoption (a fetch held across it, a burst sharing one wait, the App token re-minted at the recorded scope and renewed past its hour, a revoked grant, a lapsed session, a lost race, a record naming another upstream, a retry after another process took the session or the lease); repository ids the grant no longer admits dropped before a re-mint; the janitor; and a real hub killed (and stopped) under a real device whose workload then pushes through the restored session | `pkg/gitproxy` `durable_test.go`, `durable_e2e_test.go`; `pkg/ui` `session_restore_test.go`; `tests/e2e/hubrestart_proxies_test.go`; `tests/security/sessionrecords_test.go` |
| The same without a proxy | the token file rewritten under a running workload (on the host, in a real container with `CLOOP_REFRESH_CONTAINER_E2E=1`, on a device over the v17 frame, and in a container on it with `CLOOP_AGENT_SANDBOX_E2E=1`), whose own git then fetches and pushes past the hour, with the new token scrubbed from its output | `pkg/ui` `secrets_refresh_test.go`, `pkg/executor/container` `refresh_e2e_test.go`, `pkg/executor/remote` `refresh_e2e_test.go`, `pkg/executor/agent` `driver_integration_test.go` |

The [guarantee → test table](../security/model.md#git-interception-proxy--the-package-suites)
maps each claim to its test.

### On a real device

[`scripts/e2e/gitproxy/`](../../scripts/e2e/gitproxy/README.md) tests the whole
path on hardware: a hub with the proxy on, an enrolled device, a sandbox on it
holding a guarded lease, the sandbox's own `git`, and GitHub. The workload is an
ordinary `cloop run` whose `claude` is a stand-in that runs a probe script, so a
run is deterministic and cannot work around a refusal. Its checks cover token
isolation (`T1`–`T3`), repository scoping including encoded, `.git.git`,
upper-case and `..` spellings (`P1`–`P5`), branches (`B1`–`B8`), read-only
(`R1`–`R5`), a broad PAT narrowed only by the proxy (`W1`–`W3`), and a
device-provisioned workspace (`WS1`–`WS5`). A refusal only counts if the proxy
made it, and every push re-reads the remote ref afterwards. Its first run passed
all 132 checks across runc, gVisor, a firewall admitting only the proxy, a
provisioned workspace and host mode. Its `scan` scenario pushes a leased env
value from the sandbox to GitHub in a file, a commit message, an annotated tag
and base64, then a clean commit. On its first run, from a runc container on
sgx, the push scan refused every leaking push with no ref created on GitHub, the
clean one landed, and the value appeared in no output, audit row, journal row
or database.

### On a cluster

[`tests/kube`](../../tests/kube/README.md) does the same for the Kubernetes
backend. It runs on every CI run against the hub the Helm chart installs on
kind: once as installed (one replica), and once after the job scales it to a hub
cluster of three, where a workload's git reaches members that did not mint its
session and is forwarded. The setup is the chart's `executor.gitProxy` with
`executor.monitorTLS.auto` (the hub issues the certificate, there is no
`git_ca_bundle`, and each Pod takes the CA from its run's lease Secret), a forge
in the cluster standing in for github.com, a `github_pat` grant for one
repository and one branch pattern, and a task whose workload is the same
stand-in harness. Its checks are those of the device kit that apply to a Pod:
`H1` (the helper runs, at 0550), `T1`, `C1` (the hub's CA, for the proxy's URL
only; the kube guard, whose leaf the same CA signed, is refused), `WS1`–`WS2`,
`P1`, `B1`–`B2` and `R1`. It also checks the forge's refs, the
`gitproxy.push_denied` row, and that the run's Pod and Secrets are gone. Two of
the seven gaps in the first table under limits that remain were Kubernetes-only
and found by reading the code. The first live run found an eighth that reading
had missed: [git refused the Pod's own workspace](#limits-that-remain).

---

## Limits that remain

When this page was first written, reading the code (not a failing run) turned
up seven places where the integration was incomplete. All seven were fixed in
v0.0.5:

| It was | Now |
| --- | --- |
| A Kubernetes workspace fetch authenticated as `x-access-token`, but the proxy looks a session up by its username, so every private fetch through the proxy got a 401 | The per-run `cloop-ws-<handle>` Secret carries the credential's username (the session id) beside the token, and the init container reads both from it (`pkg/executor/kubernetes`) |
| A lease's files were projected into a Pod `0400`, so `git-credential-cloop` had no execute bit and git obtained no credential from a GitHub lease | Executable files get a per-item mode of `0550`: read and execute for the Pod's group, which is how the non-root harness reaches them, and write for nobody |
| A run's lease was never renewed, so the janitor swept it fifteen minutes in (sessions closed, device files scrubbed, App tokens destroyed) | Every lease is kept alive while its run is, by `Broker.Extend`; see [how long a session lives](#how-long-a-session-lives) |
| Releasing the inner lease destroyed a `github_app` token the pinned session still presented, and on Kubernetes that happened before the init container fetched | The inner lease lives as long as the session (`gitproxy.MintRequest.OnEnd`); on Kubernetes as long as the workspace Secret; on a device with a push write-back, until the workload ends |
| Only `cloop ui` routed through the proxy; `cloop serve` and the CLI's own executors handed the forge credential over | Every other process refuses git workspaces while `executors.git_proxy` is enabled (`reconcile.routeWorkspaceSource`) |
| A virtual executor's workspace was leased as its parent device, so a grant issued to the virtual executor was chosen and then missing | The lease is taken as the virtual executor |
| Turning the proxy on or off, or moving `advertise_url`, left a device refusing its own checkout | The checkout records which repository it is of (`cloop.upstream`), and a provisioning that reaches the same repository another way re-points `origin` instead of refusing |

A later gap is closed as well: the keepalive extended a lease but not the
installation token minted for it, so a run still using GitHub an hour after
dispatch lost access. A session now
[renews its upstream token](#the-upstream-credential-renews-itself), and without
the proxy the keepalive rewrites the sandbox's token file through the executor
holding it.

The first live run on a cluster found one more gap, which no unit test could
catch because git's check runs in the container, not in the objects the driver
sends:

| It was | Now |
| --- | --- |
| A Pod's `/workspace` is an emptyDir, which root owns whatever `runAsUser` says, and git refuses a work tree another user owns. So the init container's fetch failed with *detected dubious ownership* on every cluster, and the harness's own git and the write-back would have failed after it | cloop's own git trusts a target directory that root owns, by its exact path (`gitprovision.RootOwnedTrust`; git's ownership check protects nothing against root), and the harness container gets `safe.directory=/workspace` for its git |

What remains is either intended or beyond what the hub can reach today:

1. **Not every holder can take a new token file.** A device whose agent speaks a
   protocol older than v17 is not sent one: the hub records this in the journal,
   and the run's GitHub access ends at the token's hour. On Kubernetes the run's
   Secret is patched, and the Pod reads the new token only within the kubelet's
   sync period, and only with `patch` on `secrets` in its Role. A refresh does
   not cross members of a hub cluster, so a device whose agent reconnected to
   another member mid-run keeps its first token. A `"*"` allowlist's
   `GITHUB_TOKEN` and `GH_TOKEN` are environment variables, which no refresh
   reaches.
2. **A lease session is bounded by `session_minutes`**, counted from dispatch,
   whatever the lease does. This is the operator's ceiling; set it to cover the
   longest run you expect the hub to complete.
3. **Kubernetes is tested on one cluster, not on every one.**
   [CI runs a Pod through the proxy](#on-a-cluster) on the hub the Helm chart
   installs on kind, so the two Kubernetes fixes above (the session username in
   the `cloop-ws-<handle>` Secret, and the helper's 0550) are checked by a live
   run, not only by the objects the driver sends. That run provisions the
   workspace through a pinned session, clones and pushes through a scoped one,
   refuses a push outside the grant's branches and one to a repository the PAT
   reaches but the grant does not name, and leaves nothing of the token in the
   Pod, on one replica and on a hub cluster of three, through
   [cluster forwarding](hub-cluster.md). It does not cover a `github_app` grant
   and its token refresh through a running Pod's Secret, a push write-back
   (ordinary runs do not ask a Pod for one), or a CNI that enforces
   NetworkPolicy. CI's kind cluster does not enforce it: the hub's own probe
   shows this on every run, the test reports it, and the test asserts egress
   blocking only on a cluster where the probe shows enforcement.
4. **A Pod's fetch is served across a restart only once its run is adopted.** A
   device's pinned session [is restored with its run](#a-hub-restarted-mid-run),
   and so is a Pod's. The Kubernetes driver's workspace credential source is
   built over a broker that records its leases
   (`reconcile.Options.WorkspaceBrokerOptions`, which only `cloop ui` sets). The
   lease is kept alive and named in the run's owner row with its session, and
   the process that adopts the Pod takes the lease over, restores the session
   and hands the driver its release. The driver runs it once the init
   container's fetch is confirmed, or with the workload for a push write-back
   (`TestAPodsWorkspaceSessionSurvivesARestart`; live on a cluster,
   `TestAPodsWorkspaceSurvivesItsHubBeingKilled`). What remains is listed among
   the [residual risks](../security/model.md#what-is-not-mitigated): an init
   container that fetches before the adoption waits for it, for at most a
   minute, and a Pod whose fetch waits longer fails its provisioning. Lease-path
   sessions (everything the workload's own git uses) are restored on every
   executor, including one whose lease takeover the store could not decide,
   once a retry takes the lease over.
5. **A device checkout provisioned through the proxy by a build before v0.0.5
   has no recorded upstream.** Turning the proxy on, or moving it, works for
   every checkout, because the forge URL is the new route's upstream. Turning it
   off refuses such a checkout once, with an error naming the directory to
   remove.
6. **The push scan stops accidents and naive leaks, not a workload determined to
   publish a value.** It matches the values the run was given, in the encodings
   listed under [the push scan](#the-push-scan), and nothing else. A value that
   is reversed, split across lines, hex-encoded, encrypted or compressed inside
   a file passes, and so does one shorter than eight bytes. A delta's copied
   ranges are not re-read: a value whose first half sits in a delta's base (on
   the forge, or earlier in the same pack) and whose second half the delta
   inserts is in no single object or insert the proxy reads, and passes
   (`TestScanResidualAValueSplitAcrossACopyAndAnInsertIsNotFound` pins this
   boundary). An ordinary edit does not produce that, because git's delta
   encoder copies runs of at least sixteen matching bytes and a credential's
   bytes do not already sit at the edit point, but a workload can construct
   such a pack. A workload that means to exfiltrate a credential can use its
   network anyway; the scan closes the one path every proxied push crosses.
   After a hub restart, an adopted run is scanned for its grants' re-derived
   values and, by recorded hash, for the tokens the previous process minted; a
   session token minted before its kind carried a prefix, and a re-encoded
   minted token, are not found
   ([which values a session has](#which-values-a-session-has)). A push through a
   session that no run of this process names (none today, but a session minted
   by hand) is scanned for its own upstream token only. A hub with no git proxy
   scans nothing.

---

## See also

- [Git interception proxy](../git-interception-proxy.md): the policy model, the
  session model, what the proxy does not decide, and operating it
- [Executors](executors.md): [workspace provisioning](executors.md#workspace-provisioning)
  and [secret file delivery](executors.md#secret-file-delivery), the two
  mechanisms this page routes through the proxy
- [Kubernetes access monitor](kubernetes-access.md): the same design for
  `kubectl`, in the same process
- [Secrets and egress](../guides/secrets.md): granting the credentials the proxy
  holds, and [limiting pushes to particular branches](../guides/secrets.md#limiting-pushes-to-particular-branches)
- [Virtual executors](../guides/virtual-executors.md): the firewall through which
  a sandbox on a device reaches the proxy
- [Operator runbook](../operations/runbook.md#the-git-interception-proxy): turning
  it on, session lifetime, and alerting on `gitproxy.push_denied`
- [Security model](../security/model.md#with-the-git-interception-proxy-on-the-forge-token-never-leaves-the-hub)
  and [threat model](../security/threat-model.md): what the boundary protects
  against
