# Git proxy architecture

How cloop's git interception proxy is put together inside the hub, and how each
kind of sandbox — a Pod, a local container, an edge device, a virtual executor
on one — ends up talking to it instead of to the forge.

[Git interception proxy](../git-interception-proxy.md) is the reference for what
the proxy *decides*: the policy model, ref patterns, how a refusal reaches git,
the session model, and what it deliberately does not check. This page is the map
around it: which process runs which piece, the two routes a sandbox's git
traffic takes through it, what each executor backend does to put a sandbox on
those routes, what the sandbox ends up holding, how long it holds it, and how the
arrangement fails and is observed. It ends with the [limits that remain](#limits-that-remain),
because an operator planning a deployment needs those as much as the design.

Three facts carry most of it:

- **One process.** The proxy, the registry of live sessions, and both code paths
  that mint sessions live in the hub process, `cloop ui`. There is no separate
  daemon, and there cannot be one — see
  [the minting process must be the serving process](#the-minting-process-must-be-the-serving-process).
- **Two paths.** cloop's *own* git — the fetch that provisions a project's source
  before a task — reaches the proxy through a decorated workspace credential. The
  *workload's* git — whatever the agent clones and pushes while it works —
  reaches it through a GitHub lease rewritten to point there. The two mint
  different kinds of session and are ended by different events.
- **One rule.** While the proxy runs, no forge credential — neither a PAT nor a
  GitHub App installation token — is delivered into a sandbox the hub dispatches.
  While a valid proxy section is configured but the proxy is not running, GitHub
  access fails closed; it never falls back to handing the credential over — and
  that includes every process that is not `cloop ui` and so never runs one.

- [One process, and why](#one-process-and-why)
- [Two paths into one proxy](#two-paths-into-one-proxy)
- [The policy a session carries](#the-policy-a-session-carries)
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
| `executors.git_proxy` | `pkg/config/gitproxy.go` | The section. `GitProxyConfig.Policy()` turns it into the hub's policy: `allowed_refs` (default `refs/heads/cloop/**`), create and update, delete only with `allow_delete`, fetch always. Read once, at startup, from the hub's effective configuration: `.cloop/config.yaml` with the hub's per-instance `config.ui-<port>.yaml` overlay merged in (Task 20364), so one of two dashboards sharing a directory can run the proxy without the other. There is no dashboard setting for it. See [turning it on](../git-interception-proxy.md#turning-it-on). |
| `ensureGitProxy`, `startGitProxy` | `pkg/ui/gitproxy.go` | Start the proxy once per process. Record separately whether the configuration *asked* for one (`gitProxyRequired`), so "wanted" and "running" are never the same fact. |
| `gitproxy.Registry` | `pkg/gitproxy/session.go` | Sessions keyed by id, each holding `sha256(token)` — never the token — beside the upstream credential and the policy. No HTTP in it. |
| `gitproxy.Proxy` | `pkg/gitproxy/proxy.go` | The three smart-HTTP routes. Authenticates, checks the repository, parses a push's command list, decides, and only then attaches the forge credential. |
| `gitproxycreds.Source` | `pkg/executor/gitproxycreds` | Decorates an `executor.WorkspaceCredentialSource`: leases as before, keeps the credential, mints a **pinned** session, and returns the session token together with the proxy's URL for the repository. |
| `secretbroker.GitGuard`, `gitGuard` | `pkg/secretbroker/gitguard.go`, `pkg/ui/gitguard.go` | The seam a broker hands a GitHub token through. The hub's implementation mints a **scoped** session over the grant's repository allowlist and returns what the sandbox should hold instead. |
| `deliverGuardedGitHub` | `pkg/secretbroker/githubguarded.go` | Renders a guarded GitHub lease: a session credential file, a credential helper, and a gitconfig that rewrites GitHub to the proxy. |
| `gitProxyAuditSink` | `pkg/ui/gitproxy.go` | One insert per decision into the hash-chained trail, or a `git-proxy:` line on stderr when the database is unavailable. |

### The minting process must be the serving process

A session is minted when a workload is dispatched and authenticated when that
workload's git connects, possibly much later. The registry is memory, so a
`cloop git-proxy` command in another process would authenticate against an empty
map and refuse every request the hub had authorised. Making that work would mean
a shared session store, which means the forge credential at rest in a second
place. The proxy is therefore a service *of* the hub, and a process-wide
singleton for the same reason the executor registry is one: two `Server`
instances in one process share their executors, so they must share the sessions
those executors' sandboxes present.

The [Kubernetes access monitor](kubernetes-access.md) keeps its own registry in
the same process for the same reason, and the two are deliberately shaped alike.

### Why it starts first

`ensureGitProxy` runs at the top of `bootstrapExecutors`, before the configured
executors are reconciled. Reconciliation hands the Kubernetes driver its
workspace credential source exactly once, and the driver keeps it for the life of
the process — a proxy started afterwards would route every edge device that
connected later and silently miss every Pod. Edge devices are wrapped per device,
when the hub builds that device's credential source
(`workspaceCredentialFactory` in `pkg/ui/workspace.go`), and a lease is guarded
per broker, when the broker is opened (`attachGitGuard`). Both read the singleton
at the moment they need it.

Only `cloop ui` starts a proxy, so only `cloop ui` has a wrapper to hand the
Kubernetes driver. Every other process that registers that driver — `cloop
serve`, `cloop hub doctor`, the CLI's own subcommands — gets a source that
refuses git workspaces while `executors.git_proxy` is enabled
(`routeWorkspaceSource` in `pkg/executor/reconcile`), rather than one that hands
the Pod the forge credential. `cloop serve` says so at startup.

### Two seams, so nothing below the hub knows

No driver imports `pkg/gitproxy`, and neither does `pkg/secretbroker`:

- **The workspace path is a decorator.** Interception is a property of the
  deployment, not of a grant — the same GitHub grant is right whether or not a
  hub routes through a proxy. `pkg/executor/gitcreds` stays solely about "which
  grant authorises this repository", `gitproxycreds` adds "and how the sandbox
  reaches it", and a driver sees only an `executor.WorkspaceAccess`: a
  credential and the URL it is good against, travelling together.
- **The lease path is an interface.** The broker is the lower layer and brokers
  credentials for workloads that have nothing to do with git, so it must not
  import the proxy. `GitGuard` is the seam: the broker offers a token and gets
  back a substitute credential, or a deliberate "not guarding this one" (a hub
  with no proxy), or an error that takes the GitHub material with it.

---

## Two paths into one proxy

| | Workspace path | Lease path |
| --- | --- | --- |
| **Whose git** | cloop's: the fetch that materialises the project's source before the harness starts, and — where a Spec asks for it — the write-back push after it | the workload's: `git clone`, `git fetch`, `git push`, submodules, `go get` — whatever the agent runs |
| **Which grant** | a GitHub grant admitting the project's own repository — see [granting a PAT for workspace provisioning](../guides/secrets.md#granting-a-pat-for-workspace-provisioning) | every `github_pat` and `github_app` grant to the project — see [GitHub repositories and PATs](../guides/secrets.md#github-repositories-and-pats) |
| **Minted by** | `gitproxycreds.Source.ForWorkspace`, in the driver, at dispatch | `gitGuard.GuardGitHub`, while the broker builds the run's lease, at dispatch |
| **Session shape** | **pinned** — exactly the workspace's `owner/name` | **scoped** — the grant's `owner/name` glob allowlist |
| **Upstream** | the workspace's own https origin, any forge | `https://github.com`, fixed |
| **Policy** | the hub's, with the grant's branch list as `RestrictRefs` | the hub's, narrowed by `guardPolicy` — see [below](#the-policy-a-session-carries) |
| **Reaches git as** | a credential in the environment of **one git child**, as an origin-scoped `http.<origin>.extraHeader` — never on disk | three files in the lease directory and a few environment variables |
| **How git finds the proxy** | the workspace's `Repo` is replaced by `Minted.RepoURL`, so the fetch and any push aim at it | the lease's gitconfig rewrites `https://github.com/`, `git@github.com:` and `ssh://git@github.com/` to it |
| **Ended by** | its TTL (`session_minutes`), the hub shutting down, or — when the sandbox never presented it — the driver handing it back; the lease behind it is released when it ends | the release of the lease that minted it, else its TTL — see [how long a session lives](#how-long-a-session-lives) |
| **Session actor** | `ui` | the credential's owner for a personal secret, else the lease's actor |

### The workspace path

```
hub, at dispatch                                 edge device / Pod
────────────────                                 ─────────────────
the driver asks its credential source for the workspace
  gitproxycreds.Source.ForWorkspace
    ├─ inner source leases the grant, as held by a proxy
    ├─ Registry.Mint  pinned to owner/name, upstream = the origin,
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

The inner source is asked through `HeldSource.ForProxiedWorkspace` when it
offers it, which `gitcreds.BrokerSource` does. That marks the lease request
`GitHubProxied`, telling the broker the credential will stay on the hub — and it
is what lets a grant limited to certain branches keep its push. The broker
withholds the push from a branch-restricted GitHub credential headed into a
sandbox, because nothing in a sandbox can hold a push to a branch; it has no
reason to withhold it from one the proxy will hold.

Four behaviours of the decorator are worth knowing by name:

- **It fails closed.** A session that cannot be minted fails the dispatch and
  releases the inner lease. Falling back to the direct credential would deliver
  it at precisely the moment the boundary is broken.
- **A public repository passes through.** An empty credential is an anonymous
  fetch; there is nothing to keep off the sandbox, so no session is minted.
- **The lease lives as long as the session.** The inner lease is released when
  the session ends — closed, reaped after its TTL, or closed with the hub —
  through the registry's `OnEnd` hook, not when the driver has delivered the
  credential. For a `github_app` grant, releasing the lease destroys the
  installation token at GitHub, and the session presents that token upstream for
  its whole life; released at delivery, it left the session holding a dead token,
  and on Kubernetes the fetch itself met one. The release a driver is handed now
  closes the session only if nothing ever authenticated with it — a dispatch that
  failed before the fetch — so a used session keeps its TTL for the write-back.
- **The credential and the URL travel together.** A driver that took the token
  and ignored `Repo` would aim the sandbox at the forge holding a token the forge
  has never heard of — a loud failure, never a quiet return to the direct path.

How the credential is kept out of the Spec, argv, disk and logs on its way to the
one git child is in [the security model](../security/model.md#workspace-provisioning);
the proxy changes *what* travels that path, not the path. The persisted and
audited copy of the Spec keeps naming the real repository — an operator reading
a run row wants `github.com/acme/tool`, not a proxy URL whose session died with
the run.

**What production drives through it today is the fetch.** The write-back push
(`WriteBackPush`) is implemented end to end, but nothing in the hub asks for it:
`cloop task reproduce` and `cloop hub doctor --smoke` ask for a bundle, which is
returned over the executor's own channel and needs no forge credential at all.
The pushes a running hub actually sees come from workloads, on the lease path.

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
                                                     upstream https://github.com,
                                                     policy guardPolicy(...)
             deliverGuardedGitHub ─▶ git-proxy-credential, git-credential-cloop, gitconfig
  the driver puts the files in the sandbox's lease directory

sandbox, while the lease is live
  git clone https://github.com/acme/tool
    ├─ gitconfig: url."https://<proxy>/".insteadOf https://github.com/
    ├─ git asks the helper; it answers for the proxy's host and no other
    └─ GET https://<proxy>/acme/tool/info/refs?service=git-upload-pack
proxy: authenticate ─ acme/tool inside the allowlist? ─ … ─ forward to
       https://github.com/acme/tool.git with the token

lease released ─▶ closeGuardedSessions ─▶ Registry.Close(id, "lease released")
```

The broker never learns what is on the other side of the seam. It takes three
things from the result: the substitute credential, whether the session is
read-only, and the ref patterns a push must match — the last two only so the
workload can be told. It checks one thing before trusting the result: a guard
that handed back the very token it was given would undo the exchange while
looking identical to a working one, so `deliverGuardedGitHub` compares the two,
in constant time, and refuses a match.

For a `github_app` grant the order matters. The installation token is minted
first — at the grant's full permissions, because the proxy will enforce the
branch list — and recorded for revocation before either delivery branch can
fail, so a token that exists at GitHub is always one the hub knows to destroy.
If the guard then fails, the token is revoked at GitHub on the spot.

### Where the two paths meet

A project whose directory is a checkout of a granted repository uses both. An
edge device provisions it through a pinned session, and the checkout's `origin`
is left pointing at the proxy's URL for that repository — with no credential in
`.git/config`. When the workload later pushes from that checkout, its git asks
for a credential for the proxy's host, and the lease's helper — which answers for
exactly that host — supplies the **lease's** session. The proxy finds the
repository inside the grant's allowlist and applies the lease's policy.

So in that shape two sessions cover one repository: the pinned one for cloop's
own fetch, the scoped one for everything the workload does. The device checks
`WS2` and `WS3` in [the live kit](#on-a-real-device) assert the first half — the
provisioned origin is the proxy and holds no credential — and `WS4` and `WS5`
the second: the workload's pushes from it follow the grant.

---

## The policy a session carries

A session's policy starts as the hub's and can only lose authority on its way to
a sandbox. The composition rules themselves are in
[narrowing by grant](../git-interception-proxy.md#narrowing-by-grant-restrictrefs);
this is who applies which step.

| Dimension | Workspace path | Lease path (`guardPolicy`) |
| --- | --- | --- |
| Ref allowlist | the hub's `allowed_refs` | the same, copied — never shared |
| Create, update | as the hub allows | dropped unless the grant carries `contents:write` (or `contents`, or `*`); a PAT grant with no `--permissions` is read-only, whatever the PAT itself could do |
| Delete | as the hub allows (`allow_delete`) | never, whatever the grant or the hub says |
| Branches | the grant's list becomes `RestrictRefs` | the same, and only on a session that can write |
| Fetch | inherited — the hub's policy always sets it | inherited, never forced on |

`guardPolicy` copies the hub's allowlist before narrowing anything: `Policy` is
copied by value but shares its slice, and a narrowing written through the shared
backing array would narrow the hub's policy for every later session.
`gitproxycreds` clears `RestrictRefs` before setting it for the same reason, so
one grant's branch list never reaches the next workspace's session.

**The workload is told the result.** A guarded lease announces
`CLOOP_GIT_PROXY_MODE` (`read-only` or `read-write`), and on a session that can
push, `CLOOP_GIT_PUSH_REFS` (the hub's ceiling) and `CLOOP_GITHUB_PUSH_BRANCHES`
(the grant's list). `cloop run` reads them back in `pkg/pm/repoaccess.go` and
renders the task prompt's *Repository access* section from them, so the agent
chooses a branch the proxy will accept instead of learning the policy one refused
push at a time. For a read-write grant on `acme/tool`, on a hub that kept the
default ceiling, that section reads in full:

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

"Do not change the remote URL" is load-bearing. The rewrite happens in git's
transport, so a clone's `origin` still reads `https://github.com/acme/tool`; a
workload that "fixed" it to point anywhere else would step outside the rewrite
and find no credential.

---

## Executor by executor

Which of the two paths a backend takes part in, how the lease's files reach the
workload, and where git runs relative to the proxy:

| Executor | Workspace path | Lease files reach the workload | Where the workload's git runs | `advertise_url` must be reachable from |
| --- | --- | --- | --- | --- |
| `localprocess` | not used: a `bind` workspace, the operator's own checkout | the hub's own tmpfs directory (`/dev/shm/cloop-lease-…`), read in place | on the hub's host, as the hub's user | the hub's host — the loopback default works |
| `container` — runc, gVisor, Kata | not used: a `bind` workspace | a per-run tmpfs the driver stages, bind-mounted read-only at `/run/cloop/cloop-lease-<slug>` | inside the container | the container's network, which is `none` unless configured |
| `kubernetes` | the `workspace` init container fetches (`cloop workspace provision`), wrapped at reconciliation; the per-run `cloop-ws-<handle>` Secret carries the session id as `CLOOP_WORKSPACE_USER` beside the token | a per-run `Secret`, projected read-only at `/run/cloop/cloop-lease-<slug>`: files `0400`, the credential helper `0550` so git can run it | in the harness container | the Pod network — the hub's `Service` |
| `remote`, host mode | the agent fetches on the device before the harness starts, holding the session credential in its memory | the start frame's `secret_files`; the agent writes them into its own `cloop-lease-*` tmpfs and relocates the paths | on the device, as the agent's user | the device |
| `remote`, container mode, and every virtual executor | as host mode: the fetch runs on the device **host**, never inside the container | as host mode, then bind-mounted read-only into the container | inside the container on the device | from inside that container: its network or firewall must admit the proxy |

A few consequences follow from that table.

- **The `container` driver never touches the workspace path, but its sandboxes
  are on the lease path.** A local container with a GitHub grant clones through
  the proxy like any other sandbox, and on the driver's default
  `network: none` it cannot reach it at all.
- **On an edge device the two paths use different networks.** The provisioning
  fetch runs in the agent, on the device host, with the host's routing and the
  agent's environment; the session credential for it travels on the start frame
  beside the Spec and never enters a container. The workload's own git runs
  wherever the payload runs — in container mode, behind the container's network
  and the executor's firewall. A device can therefore provision a workspace
  through the proxy and still have a sandbox that cannot reach it.
- **Virtual executors borrow their parent's credential source, not its
  identity.** A virtual executor has no workspace source of its own; its
  dispatch goes through the parent device's, which leases as the virtual
  executor (`executor.WithRequestingExecutor`). So the grant chosen before
  dispatch, the workspace lease and the workload's own lease all match the same
  subject: a grant issued `--to executor:<virtual id>` provisions the workspace,
  and one issued to the parent device does not reach its virtual executors.
- **`localprocess` is not a boundary for the proxy to hold.** The workload runs
  as the hub's own user. The proxy still keeps the token out of the lease
  directory there, but a process that can read the hub's database can read
  everything the proxy protects — which is what `executors.allow_host_process:
  false` exists to rule out; see
  [the no-host-execution guarantee](../security/model.md#the-no-host-execution-guarantee).
- **Features never leave the host.** [Parallel features](../guides/features.md)
  are refused on executors that isolate from the host, so their workspace is
  always `bind`. `cloop feature pr` pushes with the lease's environment — through
  the proxy where the project holds a guarded grant, so into `cloop/**` — and
  opens the pull request against the GitHub REST API directly, which the proxy
  does not carry.

Where the files land and how each driver wipes them is in
[secret file delivery](executors.md#secret-file-delivery); where each driver's
fetch runs is in [workspace provisioning](executors.md#workspace-provisioning).

---

## What the sandbox holds

### On the workspace path

Nothing on disk. The session credential is given to the single git child that
fetches as an origin-scoped `http.<https://proxy/>.extraHeader`, through git's
`GIT_CONFIG_COUNT` environment protocol, alongside `GIT_CONFIG_GLOBAL=/dev/null`,
`GIT_CONFIG_NOSYSTEM=1`, an empty `credential.helper` and
`http.followRedirects=false`. The checkout's own `.git/config` records the
remote — the proxy's URL — and no authority. The
[four absences](../security/model.md#the-four-absences) apply unchanged; the only
difference is that what they keep out of view is now worth one repository for one
TTL.

### On the lease path

Three files in the lease directory:

```
git-proxy-credential   0600   username=<session id>
                              password=<session token>
git-credential-cloop   0700   the helper below
gitconfig              0600   the configuration below; GIT_CONFIG_GLOBAL names it
```

The gitconfig, exactly as rendered for a proxy advertised at
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

Three details in those are deliberate:

- **The ssh forms are rewritten too.** A sandbox has no ssh key, so a
  `git@github.com:acme/tool` remote — from a submodule, say — would simply fail;
  rewriting it turns a dead end into a fetch the grant may well authorise.
- **The helper answers for the proxy's host and nothing else.** Not to protect
  the session token, which is worthless elsewhere, but to protect the rewrite: a
  helper that answered for `github.com` would hand a workload that pointed its
  remote back at GitHub a credential that fails there with an obscure error,
  instead of git's own "could not read Username", which leads somewhere.
- **The base is re-rendered, not copied.** It is parsed, rebuilt from its scheme
  and host, and the host checked against a narrow character set, because it is
  written inside a quoted gitconfig section header and into a shell script.

The environment beside the files, none of it a credential:

| Variable | Value |
| --- | --- |
| `GIT_CONFIG_GLOBAL` | `<lease dir>/gitconfig` |
| `CLOOP_LEASE_DIR` | the lease directory, which the gitconfig finds the helper through |
| `CLOOP_GIT_PROXY_URL` | the proxy's base, `https://hub.internal:8443` |
| `CLOOP_GIT_PROXY_SESSION` | the session id — how the hub finds the session to close when the lease is released. It is the non-secret half of the credential and appears on every audit row |
| `CLOOP_GIT_PROXY_MODE` | `read-only` or `read-write` |
| `CLOOP_GITHUB_REPO_ALLOWLIST` | the grant's repositories, e.g. `acme/*` |
| `CLOOP_GITHUB_PERMISSIONS` | the grant's permissions, when it lists any |
| `CLOOP_GIT_PUSH_REFS` | read-write only: the hub's ceiling, e.g. `refs/heads/cloop/**` |
| `CLOOP_GITHUB_PUSH_BRANCHES` | read-write only, when the grant lists branches |

What is **not** there is the point: no `github-token` file, no `GITHUB_TOKEN` or
`GH_TOKEN` — even for a `*` allowlist, where an unguarded delivery exports them —
and no `CLOOP_GITHUB_TOKEN_EXPIRES_AT`, because there is no GitHub token in the
sandbox to expire. One consequence to plan for: `gh`, and anything else that
speaks GitHub's REST or GraphQL **API**, has nothing to authenticate with. The
proxy carries git's smart-HTTP protocol and nothing else.

---

## Which credential reaches the sandbox

What a GitHub grant turns into depends on whether the proxy is running, on the
grant's kind, and on whether the grant restricts branches.

**The lease path** — the workload's own git:

| This hub | `github_pat` | `github_app` | Grant with a branch list |
| --- | --- | --- | --- |
| **Runs the proxy** | a scoped session; read-only unless the grant has `contents:write` | an installation token minted for the lease and held by the hub; a scoped session in the sandbox | enforced by the proxy, outside the sandbox |
| **Has a valid `enabled: true` section, but no proxy running** | not delivered (`ErrGuardUnavailable`); the rest of the lease still is, and the run starts without GitHub access | the same, and the minted token is revoked at GitHub | not delivered |
| **Has no proxy** | the PAT itself in `github-token`, released by an in-sandbox helper for allowlisted repositories only | the installation token itself in `github-token`, which GitHub has already scoped to the grant | `github_app`: minted **read-only**, with the reason in `CLOOP_GITHUB_WRITE_WITHHELD`. `github_pat`: **not delivered** (`ErrBranchesUnenforced`) |

**The workspace path** — cloop's own fetch:

| This hub | Any GitHub grant | Grant with a branch list |
| --- | --- | --- |
| **Runs the proxy** | a pinned session for the one repository | kept writable, because the proxy holds the credential (`GitHubProxied`) |
| **Has a valid `enabled: true` section, but no proxy running** | the dispatch is refused with `ErrWorkspaceUnavailable`, naming the section rather than a missing grant | the same |
| **Has no proxy** | the forge token itself, on one git child | `github_app`: minted read-only — the fetch works, a push would not. `github_pat`: refused (`ErrBranchesUnenforced`) |

Where that is decided in code: `githubMaterial` and `githubAppMaterial` in
`pkg/secretbroker/material.go` for the lease path, `gitproxycreds.Source` and
`unavailableWorkspaceSource` for the workspace path, and `attachGitGuard`, which
attaches `gitGuard` to a broker on a hub with a running proxy, an
`UnavailableGitGuard` on a hub whose configured proxy is not running, and nothing
on a hub with none. `branchEnforcement` renders the same rule for the dashboard,
and `TestBranchEnforcementTellsTheTruthAboutThisHub` holds the two together.

"Valid" is doing work in those tables. A section that is `enabled: true` but
cannot produce a usable proxy — no `cert_file` or `key_file`, an unusable
`listen_addr` or `advertise_url` — is switched **off** when the configuration is
loaded, with a `warning: config executors.git_proxy.…` line, and the hub then
behaves as one with no proxy: credentials are delivered into sandboxes. Only a
section that loads cleanly and whose proxy then fails to start fails closed. See
[how it fails](#how-it-fails).

The one row that is not a boundary is a hub with no proxy and a grant with no
branch list: the credential is in the sandbox, and a PAT's allowlist is then
enforced against *git*, not against a workload that reads the token file. See
[the helper's limit](../guides/secrets.md#the-helpers-limit-and-what-removes-it).

---

## The network between sandbox and proxy

### From the sandbox to the proxy

`listen_addr` is where the proxy binds; `advertise_url` is what becomes the
sandbox's remote, and it has to resolve and route from wherever git runs — which
the table [above](#executor-by-executor) says, and which the
[table of forms](../git-interception-proxy.md#advertise_url-what-the-sandbox-can-reach)
turns into URLs. Nothing opens the path for you: **no firewall, egress filter or
`NetworkPolicy` cloop renders allows the proxy's address on its own.** Each
backend's network has to admit it:

| Sandbox network | What it takes |
| --- | --- |
| `network: none` — the `container` driver's default, and a virtual executor's with neither a firewall nor a `network` | Nothing reaches the proxy. The lease path fails with `Could not resolve host` or a connect error. Give the executor a network or a firewall. |
| A bridge with no filter | The advertised host has to resolve and route from the container: `host.docker.internal` or `host.containers.internal` for a hub on the same machine, a routable address otherwise. |
| `egress_filter` with direct egress | Private address space is in the block set unless named, so the proxy's address needs an `allow_cidrs` entry, its port an `allow_ports` entry, and its name a resolver in `resolvers`. |
| `egress_filter` with `internal: true` | The sandbox's network has no route off the host, so the proxy must be advertised at an address on that network, the way the [egress broker](../reference/configuration.md#scoped-network-egress) is, with a certificate that covers it. |
| A virtual executor's firewall | The same as direct egress: `allow_cidrs` with the hub's address, `allow_ports` with the proxy's port, and a resolver — `{"allow_cidrs": ["<hub-ip>/32"], "allow_ports": [<port>], "resolvers": ["1.1.1.1"]}` is the minimal one. The device's agent needs the packet-filter grant for any firewall — the installer's default; `sudo cloop executor agent install --upgrade --packet-filter` adds it to a device installed without it. |
| Kubernetes, egress filter off | No `NetworkPolicy` is created; the Pod reaches whatever the cluster routes. |
| Kubernetes, egress filter on | Each Pod's policy admits only the configured ranges and ports and cluster DNS, and has no peer for the proxy — add the hub's address range and port. |
| A project whose `.cloop/sandbox.yaml` sets `capabilities.egress: public` | Every private address is dropped for that project's sandboxes, on the container driver and on Kubernetes alike — including a proxy on a private address, a `Service` IP or the host bridge. Advertise the proxy at a public address, or drop the scope for that project. |

`cloop hub doctor`'s `gitproxy.advertise_reachable` dials the advertised address
from the **hub**, bounded to a few seconds, which proves something is listening
and nothing about the sandbox's route to it. The only check of the sandbox's side
is a clone from inside one.

The sandbox's git validates the proxy's certificate, not the hub's HTTP client.
For the workspace fetch that is the trust store of the machine the fetch runs on
— the device host, or the harness image in a Pod's init container — plus the
transport variables `pkg/executor/gitprovision` forwards: `GIT_SSL_CAINFO`,
`GIT_SSL_CAPATH`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, and the `HTTPS_PROXY` /
`ALL_PROXY` / `NO_PROXY` family. For the lease path it is the sandbox image's
trust store. See
[the certificate the sandbox has to trust](../git-interception-proxy.md#the-certificate-the-sandbox-has-to-trust).

### From the proxy to the forge

The upstream leg is the hub's own outbound traffic, and it is shaped so a request
cannot steer it:

- **The host is the session's.** A pinned session forwards to the workspace's
  own origin, which may be any https forge; a scoped session forwards only to
  `https://github.com`, a constant in `pkg/ui/gitguard.go` rather than a setting,
  because presenting a user's GitHub token to another host is not something a
  configuration value should be able to do.
- **Redirects are refused**, so a forge cannot move the credential to a host the
  session was never scoped to.
- **The hub's own environment applies.** The hub builds the upstream transport
  with no options, so it honours `HTTPS_PROXY` and `NO_PROXY` from the hub's
  environment — a hub behind a corporate proxy reaches the forge the way its
  other traffic does — and verifies the forge against the hub host's system
  roots, which Go extends with `SSL_CERT_FILE` and `SSL_CERT_DIR`. That is the
  way to trust a forge behind a private CA; `gitproxy.Options.Transport` exists
  for code embedding the package, not as a hub setting, and nothing offers to
  switch verification off.
- **Timeouts** are 15 s to connect and 60 s for the forge to start replying, with
  no overall ceiling, because a clone of a large repository is legitimately slow.

---

## How long a session lives

The two paths end their sessions on different events, and the difference is
operational, not cosmetic.

**A workspace session lives for its TTL.** `session_minutes`, 60 by default and
720 at most, counted from dispatch. Nothing closes it when the run ends, because
the fetch happens at the start of a run and a push write-back, where one is asked
for, at the end; a session closed at delivery would refuse the push it exists to
authorise. The reaper drops it within five minutes of lapsing, and a hub shutdown
closes it with the reason *"the hub is shutting down"*. What bounds it in practice
is the fetch: the device or the init container uses it once, early. The one
early close is a session nothing ever authenticated with — the dispatch failed
before the fetch — which the driver's release closes with the reason *"workspace
credential released unused"*. Whichever way it ends, the lease behind it is
released then, and a `github_app` token with it.

**A lease session ends with the lease that minted it**, whichever of these comes
first:

| Event | Where |
| --- | --- |
| The workload reaches a terminal state and its lease is wiped | `wipeLeaseOnExit`, `pkg/ui/executor.go` |
| The dispatch fails after the lease was taken | every early return in `startWorkloadAs` |
| An operator revokes the lease, or cordons or drains the executor holding it | `revokeLeaseEverywhere`, `pkg/ui/secrets_revoke.go` |
| The identity whose credential it is gets offboarded | the offboarding lease release, `pkg/ui/offboard_api.go` |
| **The lease lapses** — the lease janitor sweeps expired leases every minute; a live run's lease is extended before it can | `sweepExpiredLeases`, `pkg/ui/secrets_revoke.go` |
| The session's own TTL runs out | the proxy refuses it at authentication |

Each of the first five runs `secretLease.Close`, which calls
`closeGuardedSessions`: every `CLOOP_GIT_PROXY_SESSION` the lease's materials
carried is closed, and its `gitproxy.session_closed` row records the reason
*"lease released"* with the session's push, fetch and denial counts. Closing the
session is what makes the release mean something — wiping the lease directory
removes the token from the sandbox, but a workload that copied it first would
otherwise keep PAT-backed access to the whole allowlist until the TTL.

A run's lease is issued at dispatch for at most `secretbroker.DefaultMaxLeaseTTL`
— **15 minutes** — and **kept alive while the run is**. Every lease the hub
issues carries a keepalive (`secretLease.keepAlive`, `pkg/ui/secrets.go`) that
checks once a minute and, when the deadline is within five minutes, extends it
in place with `Broker.Extend`: same lease, same material, a new deadline one lease
period out. Extending re-reads every grant the lease holds, so a grant revoked or
expired since dispatch refuses the extension, the lease lapses on its current
deadline, and the janitor takes the material back — a revocation still lands
within one lease period. A workload the executor reports finished is not
extended, and the keepalive stops when its holder closes the lease. Each
extension is a `secret.renew` row reading *"extended in place while its run is
live"*.

Before the keepalive (Task 20349), nothing on the dispatch path renewed a lease,
so every run's lease lapsed a quarter of an hour in: its lease sessions were
closed, an edge device scrubbed its lease files, and a `github_app` token was
destroyed at GitHub, however long the run still had to go. A push refused that
way shows a `gitproxy.rejected` row whose detail is only `gitproxy:
unauthenticated` — closing a session removes it from the registry, so a later
request presenting it is indistinguishable from one presenting a token that
never existed — and the reason is on the `gitproxy.session_closed` row before it.

What still bounds a lease session is its own TTL, `session_minutes`, counted from
dispatch: the keepalive extends the lease, not the session. Set it against the
longest run the hub is expected to complete — see
[a session's life is its TTL](../git-interception-proxy.md#a-sessions-life-is-its-ttl-not-the-runs).

A hub restart drops every session of both kinds — the registry is memory — and a
workload that survives the restart on an edge device keeps a credential that no
longer authenticates. Its next git operation gets a 401.

---

## How it fails

| What happened | What the hub says | Workspace path | Lease path |
| --- | --- | --- | --- |
| No section, or `enabled: false` | nothing | the forge credential goes to the one fetching git child | the token goes into the sandbox, helper-scoped |
| `enabled: true`, but no TLS pair or an unusable `listen_addr` / `advertise_url` | `warning: config executors.git_proxy.…` at load; the section is switched off | as if there were no section | as if there were no section |
| A valid section whose proxy did not start — port taken, certificate unreadable | `ui: git interception proxy NOT started: …` | refused with `ErrWorkspaceUnavailable`; on Kubernetes every git workspace, public ones included | GitHub material not delivered (`ErrGuardUnavailable`); the run starts without it; App tokens revoked |
| One executor could not be wrapped | `ui: executor <id> is NOT routed through the git proxy: …` | that executor's workspaces refused | unaffected |
| The audit database would not open | `ui: git proxy decisions will go to stderr, not the audit trail: …` | enforced; the evidence is on stderr, prefixed `git-proxy:` | the same |
| A session could not be minted at dispatch | the dispatch error names the repository | dispatch fails, inner lease released | that GitHub material fails, as above |
| The sandbox cannot reach `advertise_url` | git: `Could not resolve host`, `Failed to connect`, or a timeout behind a dropping firewall | the fetch fails | the workload's git fails |
| The sandbox does not trust the certificate | git: `SSL certificate problem` | the fetch fails | the workload's git fails |
| The session lapsed or was closed | git: an authentication failure (HTTP 401); a `gitproxy.rejected` row — naming the expiry if the reaper has not swept the session yet, and only `unauthenticated` once it is gone | a late push fails | late git fails — see [how long a session lives](#how-long-a-session-lives) |
| A repository outside the session's scope | HTTP 403, `session is scoped to …`; a `gitproxy.rejected` row | — | refused |
| A ref outside the policy | `! [remote rejected] … (…)`; a `gitproxy.push_denied` row | refused | refused |

Two properties of that table are deliberate, and the second is easy to miss.
A proxy the operator asked for and did not get **fails closed** — the dashboard
still boots, git workspaces and GitHub leases stop. But the fail-closed state is
decided from the configuration *after* load-time repair, so a section written
with `enabled: true` and missing TLS material is not "asked for": it is switched
off with a warning, and the hub hands out credentials as it did before the proxy
existed. Read the startup log after enabling the section — the line that proves
it is on is `ui: git interception proxy on …`, and its absence is the signal.

---

## Observing it

### The audit trail

Every decision the proxy makes is a row in `audit_events`, with `entity_type`
`gitproxy` and the session id as the entity:
[`gitproxy.session_minted`](../reference/audit-events.md#gitproxy),
[`gitproxy.fetch`](../reference/audit-events.md#gitproxy),
[`gitproxy.push_allowed`](../reference/audit-events.md#gitproxy),
[`gitproxy.push_denied`](../reference/audit-events.md#gitproxy),
[`gitproxy.rejected`](../reference/audit-events.md#gitproxy) and
[`gitproxy.session_closed`](../reference/audit-events.md#gitproxy). The payload
carries the session, the repository the request addressed, the project and task
ids, the refs and the reason — never a credential, because `gitproxy.Event` has no
field that could hold one. A request that presented no credential at all is
counted rather than audited; see
[audit events](../git-interception-proxy.md#audit-events).

Three joins answer most questions:

- **Session → everything it did.** The session id is on its mint, on every
  request row, and on its close — `cloop audit-log list --entity gitproxy`.
- **Lease → session.** A guarded lease's material names the session in
  `CLOOP_GIT_PROXY_SESSION`, and the
  [`secret.lease`](../reference/audit-events.md#secret) row written for each
  grant it delivered carries, as its `reason`, a summary of what the proxy will
  enforce: `github read-write via git proxy, repos acme/*, refs
  refs/heads/cloop/**` for a PAT — with `narrowed to …` appended when the grant
  lists branches — or `github app installation … token for … (proxy-guarded,
  read-write), expires …` for an App. The Secrets panel's live-lease table shows
  the same summary.
- **Workspace fetch → grant.** The
  [`workspace.provision_start`](../reference/audit-events.md#workspace) and
  `workspace.provision_end` rows name the grant and lease that authorised the
  fetch, and name the real repository rather than the proxy's URL.

### Metrics

`cloop_gitproxy_pushes_total{result}`, `cloop_gitproxy_push_denials_total{reason}`
and `cloop_gitproxy_anonymous_requests_total`, on the hub's `/metrics`. They count
pushes only — a fetch, a session, and a refusal before any ref was decided (a
repository outside scope, a session that cannot push asking for the
receive-pack advertisement) appear in the audit trail and in no counter. See
[metrics](../operations/metrics.md#git-interception-proxy).

### `cloop hub doctor`

The `gitproxy` checks read the same configuration the hub does:
`gitproxy.enabled`, `gitproxy.tls`, `gitproxy.advertise_url`,
`gitproxy.advertise_reachable` (the bounded dial from the hub), `gitproxy.allowed_refs`
(patterns outside `refs/heads/cloop/`), `gitproxy.allow_delete`, and — with the
proxy off — `gitproxy.branch_grants`, which counts the grants whose branch list
this hub therefore delivers read-only or not at all. `--smoke` brokers a real
lease from a process that has no proxy, so on a hub with the section enabled it
attaches an `UnavailableGitGuard` and refuses GitHub material rather than writing
a token into its smoke sandbox.

### The dashboard

A project's **Repository access** panel reads `git_proxy` from
`GET /api/projects/{idx}/repositories` — whether a proxy is running, whether one
is required, and the hub's push ceiling — and shows under the branch field what a
list will amount to on this hub. In the Secrets panel, a grant that lists
branches carries `branch_enforcement` — `proxy`, `unavailable`, `read_only` or
`not_delivered` — and a `github_pat` or `kubeconfig` grant carries `enforcement`,
`proxy` or `unguarded`. The second is coarser than the first: a hub whose
configured proxy is down reports `unguarded` there, although its GitHub leases
then fail rather than deliver. The listen address, certificate path and session
count are deliberately in neither view: none helps anyone choose a branch, and
all of it is reconnaissance.

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
| Workspace credentials in a Pod | the session id reaches the init container through the run's Secret, the helper is projected executable, and the lease behind the token lives as long as that Secret | `pkg/executor/kubernetes` `workspace_test.go`, `secretfiles_test.go` |
| Session and lease lifetimes | a pinned session releases its lease exactly once when it ends, an unused one is closed on release, a lease is extended only while its grants hold and its run is live | `pkg/gitproxy` `session_test.go`, `pkg/executor/gitproxycreds`, `pkg/secretbroker` `extend_test.go`, `pkg/ui` `secrets_keepalive_test.go` |
| Live GitHub, opt-in | a grant assigned through the panel's endpoint pushes through the proxy to a real repository — outside its branches refused, inside them landed, no token in the sandbox | `TestLiveBranchRestrictionThroughTheGitProxy` in `pkg/ui` |

The [guarantee → test table](../security/model.md#git-interception-proxy--the-package-suites)
maps each claim to its test.

### On a real device

[`scripts/e2e/gitproxy/`](../../scripts/e2e/gitproxy/README.md) proves the whole
path on hardware: a hub with the proxy on, an enrolled device, a sandbox on it
holding a guarded lease, the sandbox's own `git`, and GitHub. The workload is an
ordinary `cloop run` whose `claude` is a stand-in that runs a probe script, so a
run is deterministic and cannot "helpfully" work around a refusal. Its checks
cover token isolation (`T1`–`T3`), repository scoping including encoded,
`.git.git`, upper-case and `..` spellings (`P1`–`P5`), branches (`B1`–`B8`),
read-only (`R1`–`R5`), a broad PAT narrowed only by the proxy (`W1`–`W3`), and a
device-provisioned workspace (`WS1`–`WS5`). A refusal only counts if the proxy
made it, and every push re-reads the remote ref afterwards. Its first run, in
Task 20346, passed all 132 checks across runc, gVisor, a firewall admitting only
the proxy, a provisioned workspace and host mode.

What it does not cover is the Kubernetes backend, where nothing yet exercises
the proxy end to end — which is why two of the seven gaps in
[limits that remain](#limits-that-remain) were found only by reading.

---

## Limits that remain

This section used to list seven places where the integration was incomplete,
found while this page was first written (Task 20347) by reading the code rather
than by a failing run. Task 20349 closed all seven:

| It was | Now |
| --- | --- |
| A Kubernetes workspace fetch authenticated as `x-access-token`, and the proxy looks a session up by its username, so every private fetch through the proxy met a 401 | The per-run `cloop-ws-<handle>` Secret carries the credential's username — the session id — beside the token, and the init container reads both from it (`pkg/executor/kubernetes`) |
| A lease's files were projected into a Pod `0400`, so `git-credential-cloop` had no execute bit and git obtained no credential from a GitHub lease | Executable files get a per-item mode of `0550`: read and execute for the Pod's group, which is how the non-root harness reaches them, and write for nobody |
| A run's lease was never renewed, so the janitor swept it fifteen minutes in — sessions closed, device files scrubbed, App tokens destroyed | Every lease is kept alive while its run is, by `Broker.Extend`; see [how long a session lives](#how-long-a-session-lives) |
| Releasing the inner lease destroyed a `github_app` token the pinned session still presented, and on Kubernetes that happened before the init container fetched | The inner lease lives as long as the session (`gitproxy.MintRequest.OnEnd`); on Kubernetes as long as the workspace Secret; on a device with a push write-back, until the workload ends |
| Only `cloop ui` routed through the proxy; `cloop serve` and the CLI's own executors handed the forge credential over | Every other process refuses git workspaces while `executors.git_proxy` is enabled (`reconcile.routeWorkspaceSource`) |
| A virtual executor's workspace was leased as its parent device, so a grant issued to the virtual executor was chosen and then missing | The lease is taken as the virtual executor |
| Turning the proxy on or off, or moving `advertise_url`, left a device refusing its own checkout | The checkout records which repository it is of (`cloop.upstream`), and a provisioning that reaches the same repository another way re-points `origin` instead of refusing |

What remains is either deliberate or beyond what the hub can reach today:

1. **A GitHub App token lives GitHub's hour.** The keepalive extends a lease,
   not the installation token minted for it at dispatch — in the sandbox without
   a proxy, and upstream of the session with one. A run that still needs GitHub
   more than an hour after dispatch loses it then. `Broker.Renew` mints a fresh
   token, but nothing can yet hand a running sandbox new material, or swap the
   credential a live session presents upstream.
2. **A lease session is bounded by `session_minutes`**, counted from dispatch,
   whatever the lease does. That is the operator's ceiling by design; set it
   against the longest run the hub is expected to complete.
3. **Nothing exercises the proxy end to end on Kubernetes.** The fixes above are
   pinned by unit tests against the objects the driver sends the API server; no
   test yet runs a Pod through the proxy, the way
   [the live kit](#on-a-real-device) runs a device.
4. **A device checkout provisioned through the proxy before Task 20349 has no
   recorded upstream.** Turning the proxy *on*, or moving it, works for every
   checkout, because the forge URL is the new route's upstream; turning it
   *off* refuses such a checkout once, naming the directory to remove.

---

## See also

- [Git interception proxy](../git-interception-proxy.md) — the policy model, the
  session model, what the proxy does not decide, and operating it
- [Executors](executors.md) — [workspace provisioning](executors.md#workspace-provisioning)
  and [secret file delivery](executors.md#secret-file-delivery), the two
  mechanisms this page routes through the proxy
- [Kubernetes access monitor](kubernetes-access.md) — the same design for
  `kubectl`, in the same process
- [Secrets and egress](../guides/secrets.md) — granting the credentials the proxy
  holds, and [limiting pushes to particular branches](../guides/secrets.md#limiting-pushes-to-particular-branches)
- [Virtual executors](../guides/virtual-executors.md) — the firewall a sandbox on
  a device reaches the proxy through
- [Operator runbook](../operations/runbook.md#the-git-interception-proxy) — turning
  it on, session lifetime, and alerting on `gitproxy.push_denied`
- [Security model](../security/model.md#with-the-git-interception-proxy-on-the-forge-token-never-leaves-the-hub)
  and [threat model](../security/threat-model.md) — what the boundary is worth
