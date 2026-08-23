# Git interception proxy

How a sandbox is allowed to push to some branches and not others, without ever
holding a credential that could reach the others.

`pkg/gitproxy` is a git smart-HTTP proxy that runs **outside** the sandbox. The
sandbox's remote points at it, the sandbox authenticates with an ephemeral
session token, and the proxy — holding the real forge credential — parses the
push's ref-update list, checks every update against the session's policy, and
only then presents the credential upstream. The branch allowlist stops being
something the sandbox is asked to honour and becomes a property of the network
path.

The proxy runs **inside the hub process** and is **off by default**. An
unconfigured hub behaves exactly as [the hole it closes](#the-hole-it-closes)
describes: the forge credential is delivered into the sandbox and the branch
rule is a convention. Setting `executors.git_proxy.enabled: true` turns it on,
and from then on every git workspace the hub provisions — Kubernetes Pods and
enrolled edge devices alike — clones and pushes through it. See
[operating it](#operating-it).

- [The hole it closes](#the-hole-it-closes)
- [The inversion](#the-inversion)
- [The policy model](#the-policy-model)
- [Session lifecycle](#session-lifecycle)
- [What it does not decide](#what-it-does-not-decide)
- [Operating it](#operating-it)
- [Audit events](#audit-events)
- [Threat model notes](#threat-model-notes)

---

## The hole it closes

With the proxy off — the default, and what an un-configured hub does — the push
write-back runs `git push` *in the sandbox*. `pkg/executor`
requires every write-back branch to sit under `cloop/`
(`executor.ValidateWriteBackBranch`), and `pkg/writeback` re-verifies the branch
when the result arrives. Both checks are real, and neither is a boundary:

- `ValidateWriteBackBranch` runs inside `pkg/executor/gitwriteback`, which is
  code the **sandbox itself executes** — on the edge device via the remote
  agent, or as `cloop workspace writeback` inside the Pod. A check the attacker
  runs is a convention.
- `pkg/writeback` inspects the branch *after* it exists. On the push transport
  the commit has already landed on the forge by the time anything on the hub
  looks at it; what the hub can still refuse is merging it, not the push.

The credential is the reason the checks cannot be more than that. In push mode
the hub leases a `github_pat` and delivers it **into** the sandbox — carefully,
as a URL-scoped `http.<origin>.extraHeader` on one git child, never on disk and
never in an argv (see
[Workspace provisioning](security/model.md#workspace-provisioning)) — because
that is where git runs. Delivery is the end of the hub's control. The sandbox
now holds an authority scoped to whole repositories and is asked politely to use
a fraction of it. A workload that ignores the SDK and runs

```
git push --force origin HEAD:main
```

reaches `main`, and the first anyone hears of it is the force-push
notification. Nothing there detects the attempt, because nothing there is on the
path.

That the ordinary write-back itself pushes with `--force` (the ref is
cloop-owned, so forcing it is correct) is worth noting only because it means the
sandbox's git is already configured for exactly the operation you would least
like it to aim elsewhere.

Turning the proxy on does not remove either check. `ValidateWriteBackBranch` and
`pkg/writeback`'s inspection stay exactly where they are; what changes is that
they stop being the only thing between the sandbox and `main`, because the
sandbox no longer holds a credential that could reach it. That is deliberate: a
hub with the proxy off, or a driver that never routed through one, keeps the
behaviour above rather than losing a check to a feature flag.

---

## The inversion

Move git's authenticated leg out of the sandbox:

```
sandbox ──session token──▶ gitproxy ──PAT──▶ github.com
                             │
                        Policy.Decide per ref
```

The sandbox's remote is rewritten to the proxy's URL for the session
(`Minted.RepoURL`, which carries no credential). It authenticates with HTTP
basic, username `Session.ID`, password the session token — a credential that is
worth nothing anywhere else, against any other repository, or after the TTL. The
proxy holds the PAT, and `upstreamRequest` is the only place it is ever
attached; it is attached to a URL derived from **the session**, not from
anything the request contained, so a crafted request cannot steer the credential
at a host of its choosing.

The request path in full:

```
POST /acme/tool/git-receive-pack
   │
   ├─ splitGitPath        exactly owner/name plus one of three endpoints,
   │                      everything else is 404 — the dumb HTTP protocol is
   │                      not served at all, because it reads objects by path
   │
   ├─ Registry.Authenticate     session id + token, constant-time, one error
   │                            for every failure
   │
   ├─ repository pin      the path must equal Session.RepoPath, else 403 —
   │                      a session minted for one repo cannot be replayed
   │                      against another the same proxy serves
   │
   ├─ requestBody         MaxPackBytes cap, transparent gzip decode
   │
   ├─ ParseReceivePack    pkt-line decode of the command section only,
   │                      capped at 1 MiB, keeping the raw bytes for replay
   │
   ├─ Policy.DecideAll    per ref: is the name allowed, is the direction
   │                      allowed. All or nothing.
   │
   ├─ push_allowed / push_denied      audit, before the forward
   │
   └─ upstreamRequest     ← the PAT is attached here, and only here
```

Four smaller properties hold the shape together:

- **Byte-identical replay.** `ParseReceivePack` returns a reader that replays
  the consumed command bytes followed by the untouched pack. Re-encoding the
  command list from the parsed struct would mean the bytes the policy inspected
  and the bytes the remote applies were produced by different code, and any
  disagreement between them is a bypass.
- **No redirects.** The client's `CheckRedirect` returns `http.ErrUseLastResponse`.
  A forge that 302s a receive-pack elsewhere would be a forge redirecting the
  hub's credential to a host the session was never scoped to.
- **Upstream error bodies are not relayed.** A `>= 400` upstream response passes
  its status through so git reports something truthful, and its body is replaced
  with `cloop git proxy: upstream returned …`. A forge's error page can quote
  the request back, and the request carried the credential. Every upstream
  header other than content type and encoding is dropped for the same reason —
  a `Set-Cookie` or `WWW-Authenticate` reaching the sandbox is the hub's session
  with the forge leaking one hop further.
- **Errors are scrubbed.** `scrub` replaces the session's upstream password in
  any error text before it reaches the sandbox.

### How a refusal is reported

A denied push is reported in whichever dialect the client can read, which is
decided by the capabilities it advertised on the first command line:

| Client asked for | What it gets |
| --- | --- |
| `report-status` or `report-status-v2` | HTTP 200 with a status report: `unpack ok` followed by one `ng <ref> <reason>` line per command. Git prints the reason next to the branch name and exits non-zero. |
| `report-status` **and** `side-band-64k` | The same report, plus a full-length explanation on side-band channel 2, which git prints prefixed `remote:`. The `ng` reason is truncated to one line; this is where the whole sentence fits. |
| Neither | HTTP 403 with the reason as text. A client with no channel for a report cannot be answered with one — a silent 200 to such a client is a push that moved nothing and reported success. |

A push refused in part is refused as a whole. Commands that would have passed on
their own get `ng … push refused as a whole because another ref was denied`.
Partially applying a push would let the sandbox map the allowlist by watching
which half of its commands landed, and would leave the repository in a state
neither side asked for.

---

## The policy model

`Policy` is what one session may do to one repository's refs. It is
deny-by-default in **every** dimension: an empty `AllowedRefs` is not "no
restriction", it is the built-in write-back namespace; an unset `AllowDelete` is
a refusal, not an omission. The failure mode of a permissive default here is a
sandbox force-pushing over `main`, which is the outcome the subsystem exists to
make impossible, so there is no default that trades safety for convenience.

### Ref patterns

`AllowedRefs` are glob patterns over **full** ref names.

| Written | Means | Matches | Does not match |
| --- | --- | --- | --- |
| `cloop/*` | `refs/heads/cloop/*` — a bare name is read as a branch and gets `refs/heads/` prepended | `refs/heads/cloop/task-42` | `refs/heads/cloop/task-42/fixup`, `refs/heads/main` |
| `refs/heads/cloop/*` | the same pattern, written out | as above | as above |
| `refs/heads/cloop/**` | any depth strictly **below** the prefix | `refs/heads/cloop/task-42`, `refs/heads/cloop/task-42/fixup` | `refs/heads/cloop` itself — a namespace is a place to put branches, not a branch |
| `refs/tags/v*` | tags whose name has no further `/` | `refs/tags/v1.2.0` | `refs/tags/v1/2` |
| `refs/**` | everything, deliberately | `refs/heads/main` | — |

Matching follows `path.Match`, so **`*` does not cross a `/`**. That is the
single most important thing to know when writing an allowlist: `cloop/*` admits
one level and a per-task namespace like `cloop/task-42/fixup` needs the `/**`
form. The `/**` suffix is handled before `path.Match` sees the pattern, as a
prefix test.

`Normalize()` fills defaults, prepends `refs/heads/` where needed and drops
duplicates; it is idempotent. `Validate()` then refuses a pattern that does not
start with `refs/`, contains `..` or `//`, ends with `/`, holds a control
character or a space, or is not a compilable glob — the last because an
uncompilable pattern would silently match nothing and read as a working
allowlist that denies everything. A whole-namespace pattern like `refs/**` is
*allowed*: an operator may configure that deliberately, and refusing it here
would only push the same decision somewhere less visible. `MaxRefPatterns` (256)
bounds the list, because matching every pattern against every ref in every push
is work an attacker would otherwise choose the size of.

### Directions

A ref update is a create, an update or a delete, determined by which side is the
all-zero object name. They are three separate authorities:

| Field | Grants | Default | Why |
| --- | --- | --- | --- |
| `AllowCreate` | bringing an allowed ref into existence | off | The ordinary write-back case, and the one authority a caller almost always wants. |
| `AllowUpdate` | moving an existing allowed ref to a new commit | off | A retried task legitimately replaces its own predecessor. |
| `AllowDelete` | removing an allowed ref | off | A write-back never needs it, and a name-only allowlist that forgot about deletes would let a sandbox destroy the very branches it was scoped to. |
| `AllowFetch` | the read half — `git-upload-pack` — over the same session | off | A sandbox that clones through the proxy needs it; one that only pushes back a tree it was handed does not. |

`Validate()` refuses a policy with all four off. A policy that permits nothing is
almost certainly a caller that built a `Policy{}` and expected defaults, and
saying so beats minting a session that refuses every request it will ever see.

### Ceilings

| Field | Default | Bounds |
| --- | --- | --- |
| `MaxCommands` | `DefaultMaxCommands` = 16 | Ref updates in one push. A write-back moves one branch; anything past a handful is a mirror push or a search for a ref the allowlist forgot. |
| `MaxPackBytes` | `DefaultMaxPackBytes` = 2 GiB | The request body. The pack is streamed, not buffered, so this is not a memory bound — it bounds what one session can push through the hub's credential in one request. |

The command section itself is separately capped at 1 MiB before any of it is
parsed, because those are the bytes the proxy must hold in memory to decide at
all.

### The default: `WriteBackPolicy()`

```go
gitproxy.WriteBackPolicy()
// Policy{
//     AllowedRefs: []string{"refs/heads/cloop/**"},  // DefaultAllowedRef
//     AllowCreate: true,
//     AllowUpdate: true,
//     // AllowDelete, AllowFetch: false
// }
```

This is the executor write-back path expressed as a boundary: create and update
inside the `cloop/` namespace, no deletes, no fetch. `DefaultAllowedRef` is
built from `executor.WriteBackBranchPrefix`, so the proxy's allowlist and the
in-sandbox convention cannot drift apart — restating the same prefix *outside*
the sandbox is precisely what turns it into a boundary.

It is a constructor rather than a documented recipe because every caller that
hand-assembled these four booleans would be a caller that could get one wrong,
and three of the four failures are silent. `Mint` applies it when the request's
policy is entirely zero-valued — `Policy.IsZero()`, which is "nobody filled this
in" and not "somebody deliberately wrote a policy that permits nothing"; the
second is a `Validate()` error, and substituting a default for it would widen a
policy an operator wrote to be narrow.

**The hub's own policy is this plus fetch.** `GitProxyConfig.Policy()` sets
`AllowFetch` unconditionally, because with a proxy interposed the provisioning
*clone* goes through it too — a hub whose sandboxes still fetched directly would
still be delivering the PAT, and would have moved the boundary onto half the
round trip. The rest comes from configuration: `allowed_refs` is the allowlist
(empty means `refs/heads/cloop/**`), `allow_delete` is the one direction an
operator can add, and create and update are always on because a write-back is
exactly those two.

### Deciding a push

`Policy.Decide` checks the **name first**, then the direction. A sandbox probing
for a ref learns the same thing either way, but an operator reading the audit
trail wants `main is not in the allowlist` rather than `delete is not
permitted`, because the first names the real problem. `DecideAll` evaluates
every command and reports whether all passed; the refusal text of each is
carried on a `Decision` and rendered as a single line, since git's status report
is newline-delimited and a multi-line message would be split into a status line
and garbage.

Before policy runs at all, each parsed command must survive `ValidateRefName` —
git's own naming rules, applied here because the proxy forwards this string to a
real git server and a name git would refuse must be refused *here* rather than
passed along. That is what keeps `refs/heads/../../x` and
`refs/heads/ --upload-pack=sh` from being this package's problem to reason
about. An update from the zero SHA to the zero SHA is refused too: harmless
upstream, but not a shape any of the three authorities describes.

One thing the object names in a command are **not** is verified. `Old` is the
client's claim about what the remote currently holds; the remote checks it, this
proxy does not, and no decision here may depend on it being true. What the proxy
depends on is only the *shape* — which side is zero — because that is what
distinguishes the three authorities.

---

## Session lifecycle

A session is one sandbox's brokered access to one repository, for one TTL, under
one policy.

### Minting

`Registry.Mint(MintRequest)` takes the upstream `https://` URL, the `Credential`
to present there, the `Policy`, a TTL, and audit labels (`ProjectID`, `TaskID`,
`ExecutorID`, `Actor`). It returns a `Minted`:

| Field | What it is |
| --- | --- |
| `Session` | the live session; `Session.ID` is the basic-auth username and is not secret |
| `Token` | the plaintext session token. **The only copy that will ever exist** — the registry keeps `sha256(token)` and nothing else |
| `RepoURL` | what the sandbox sets as its remote: the proxy's base URL plus `owner/name`. Carries no credential |

`Minted.Credential()` renders the pair a driver delivers into the sandbox.

The repository is **pinned** at mint time. `UpstreamRepoPath` parses `owner/name`
out of the upstream URL, requiring `https`, a host, and no embedded credentials;
that path is what the session is served under and what every request is compared
against. The shape is not cosmetic: `executor.Workspace`'s `RepoPath` parses
exactly this out of a clone URL to match a GitHub grant's repository allowlist,
so a proxy URL that did not preserve it would break grant matching for every
workspace routed through the proxy.

TTLs:

| Constant | Value | Meaning |
| --- | --- | --- |
| `DefaultSessionTTL` | 1 hour | Used when `MintRequest.TTL` is zero. It is the length of a task's *git traffic*, not of a task — the clone and the write-back push both happen inside it. An hour covers a slow clone of a large repository over a slow link and still expires long before a leaked token could be used at leisure. |
| `MaxSessionTTL` | 12 hours | The ceiling. A long-lived git-proxy session is indistinguishable from having handed the sandbox the credential itself. |

A TTL above `MaxSessionTTL` is an **error, not a silent clamp**: a caller that
asked for a day and got twelve hours would discover it as a failed push halfway
through.

### Authenticating

`Registry.Authenticate(id, token)` hashes the presented token unconditionally —
so an unknown session id costs the same as a known one with a wrong token — and
compares with `subtle.ConstantTimeCompare`. Unknown session, wrong token,
revoked and expired all return `ErrUnauthenticated`. They are one error on
purpose: a caller that could tell "no such session" from "wrong token" would be
an oracle for enumerating session ids. `ErrSessionNotFound` exists separately for
management calls, where the caller is the operator and precision is the point.

The hub's session TTL is `executors.git_proxy.session_minutes`, defaulting to
60 — the same hour as `DefaultSessionTTL`. A value outside
`[0, GitProxySessionMinutesUpper]` (720, i.e. `MaxSessionTTL`) is reported and
reset to the default at load rather than silently narrowed.

### A session's life is its TTL, not the run's

**Nothing closes a session when a run ends.** The credential source mints at
dispatch and hands the sandbox its token; `ForWorkspace` is not told when the
workload finished, and a session closed at the moment the credential was
delivered would refuse the write-back it exists to authorise — the sandbox
fetches at the *start* of a run and pushes at the *end*.

The consequence is a real operational limit, and it is worth stating plainly: **a
run that outlives `session_minutes` fails its push.** The proxy answers an
expired session with HTTP 401, which the sandbox's git reports as an
authentication failure, and the attempt lands in the audit trail as a `rejected`
event. Set the TTL against the longest run the hub is expected to complete, not
against the median one. The trade is deliberate — before interception the
sandbox held the PAT and its access ended never, whatever the lease said — but a
push that fails at the end of a two-hour run is an expensive way to discover a
one-hour ceiling.

### Closing and reaping

`Registry.Close(id, reason)` revokes a session and is idempotent, so a caller can
call it from a `defer` without checking whether the run already ended. The
closing audit row carries the session's counters. It is what makes revocation a
local decision: the next request is refused with no forge round-trip and no
coordination.

No command exposes it. The hub closes sessions on shutdown and nowhere else, so
an operator ending one early either restarts the hub — which closes all of them —
or waits for the TTL, which is enforced at authentication whether or not the
reaper has swept it. Revoking the underlying grant with `cloop secret revoke`
stops the *next* dispatch from minting anything; it does not reach a session
already minted.

`Registry.ReapExpired()` drops sessions past their TTL and returns how many
went. `Authenticate` already refuses an expired session, so this is hygiene
rather than enforcement — without it the map grows for the life of the process.
The hub runs it every 5 minutes, so a lapsed entry occupies memory for at most
that long after it stopped being usable.

On hub shutdown every live session is closed with the reason *"the hub is
shutting down"* rather than abandoned, so the trail records why they ended and
their counters land in the closing rows instead of disappearing with the
process.

`Session.Stats()` snapshots `Pushes`, `Fetches`, `Denied`, `BytesUp` and
`BytesDown`. The first three are what an operator actually meets, in the
`Detail` of a `gitproxy.session_closed` row; the byte counters are visible only
through `Stats()` itself. `BytesDown` counts the bytes streamed back to the
sandbox. `BytesUp` is never incremented and reads zero — worth knowing before
concluding from a counter that nothing was pushed.

---

## What it does not decide

A boundary is only useful if its edges are stated. Three things this proxy
deliberately does not do:

### Whether an update is a fast-forward

That needs the object graph — whether the old commit is an ancestor of the new
one — which the proxy does not have and would have to index a pack to get.
Fast-forward enforcement belongs where the graph already is: **the forge**.
GitHub branch protection, or `receive.denyNonFastForwards` on a self-hosted
remote.

Being explicit about this beats implying a check that cannot be made. What the
proxy enforces is *which refs* a sandbox may touch and *in which direction* —
create, update, delete — which is exactly what stops a sandbox reaching a branch
a human owns. History rewriting *inside* the sandbox's own namespace is not
something this layer refuses, and it is not something the write-back path wants
refused: the ordinary write-back force-updates its own branch.

### Signed pushes

A push carrying a push certificate is **refused outright**, with HTTP 403. With
`push-cert` the command list lives inside a signed block and the remote applies
*that* copy, so enforcing a branch allowlist against the unsigned lines would be
enforcing it against bytes nothing acts on. Refusing is the only honest answer
available without full certificate parsing and verification, and a proxy that
silently passed one through would be a branch allowlist with a documented
bypass.

### Filtering the ref advertisement

`GET /info/refs` is forwarded **unmodified**. Trimming it to the allowed refs is
the obvious move and it is wrong: a receive-pack client treats every advertised
ref as an object the remote already has and therefore need not send. Hide
`refs/heads/main` and the sandbox re-sends the entire history reachable from it
on **every** push — a multi-hundred-megabyte pack where a few kilobytes were
needed, on a link the hub is paying for, repeatedly.

The allowlist is enforced on the command list instead, where it costs nothing
and where it cannot be worked around by a client that skipped discovery
entirely. Hiding the ref names buys no security either way: a sandbox that can
read the checkout it was given already knows them.

What the advertisement *is* gated on is the coarse question — a session whose
policy permits no write cannot ask for the `git-receive-pack` advertisement, and
one without `AllowFetch` cannot ask for `git-upload-pack`. A request with no
`service` parameter is the dumb protocol and is refused, which is what keeps the
proxy's surface to the three routes above.

---

## Operating it

### TLS is not optional

`Registry.BaseURL` must be `https`, must have a host, must have no path, no
query, no fragment and no embedded credentials. `NewRegistry` and `New` both
refuse anything else.

The reason is the token: the sandbox presents it as an `Authorization` header on
*every* request, and over cleartext that token is published rather than
delivered. **A loopback proxy is not an exception.** A sandbox is by
construction something that may be sharing a host with whatever else is
listening on loopback — that is the whole premise of running the workload in one.

`Proxy.Serve(ln)` takes a listener rather than a certificate path, so the
caller configures TLS through [`pkg/tlsconf`](../pkg/tlsconf/tlsconf.go) exactly
as the hub does, and a TLS listener drops straight in — which is what the hub
does with `cert_file`, `key_file` and `min_tls_version`. `Options.Transport`
exists for the other leg: an operator whose forge sits behind a private CA
supplies a `RoundTripper`, instead of the package growing a flag that weakens
the default.

An enabled section with no `cert_file` and `key_file` does not start a cleartext
proxy: the pair is required when `enabled` is true, and a section that has one
without the other is reported and switched **off** at load. Disabling is the
safe repair precisely because the proxy is not a fallback — with it off a
workspace is provisioned the way it was before interception existed, which is a
documented behaviour rather than a new failure mode.

Timeouts are set where a stall is a bug and left off where a wait is legitimate:
15 s to dial the forge, 60 s for it to start replying, 30 s to read request
headers, 2 min idle, 30 s of grace for in-flight requests on `Close`. There is
deliberately **no** overall client timeout and no `WriteTimeout` — a clone or a
push of a large repository is legitimately slower than any ceiling worth setting,
and the request context already ends when the peer hangs up.

### Turning it on

One section in the hub's `.cloop/config.yaml`:

```yaml
executors:
  git_proxy:
    enabled: true
    listen_addr: "0.0.0.0:8443"                    # where the proxy binds
    advertise_url: "https://hub.internal:8443"     # what the SANDBOX connects to
    cert_file: /etc/cloop/tls/git-proxy.crt
    key_file: /etc/cloop/tls/git-proxy.key
    min_tls_version: "1.2"                         # or "1.3"; empty means 1.2
    session_minutes: 60                            # 0 means 60; ceiling is 720
    allowed_refs: ["refs/heads/cloop/**"]          # the default; widen deliberately
    allow_delete: false
```

`enabled`, `cert_file` and `key_file` are the only keys with no useful default.
An empty `listen_addr` binds an ephemeral loopback port, and an empty
`advertise_url` falls back to the bound address — a pair that is correct only
when the sandbox shares the hub's network namespace.

Validation is not deferred to start time. `allowed_refs` is put through the same
`Normalize()` and `Validate()` the proxy enforces with, so a pattern that would
silently match nothing is refused when it is written rather than read as a
working allowlist that denies everything; a rejected list resets to the built-in
namespace whole, because a half-applied allowlist is a policy nobody wrote. The
same is true of `session_minutes`, `min_tls_version`, `listen_addr` and
`advertise_url`. The three repairs that could only produce an unusable or unsafe
proxy — a listen address nobody chose, an advertise URL a sandbox would send a
token to in cleartext, missing TLS material — switch `enabled` **off** rather
than starting one anyway.

A hub that started the proxy says so, once, naming the bind address, what
sandboxes will be pointed at, and the allowlist in force:

```
ui: git interception proxy on 0.0.0.0:8443, advertised as https://hub.internal:8443; pushes limited to refs/heads/cloop/**
```

A hub that could not start it comes up anyway, and says exactly what is not in
effect:

```
ui: git interception proxy NOT started: git proxy listen on 0.0.0.0:8443: bind: address already in use
    executors.git_proxy is enabled, so no git workspace can be provisioned:
    dispatches needing one will be refused rather than handed the forge
    credential directly. Fix the section or set enabled: false.
```

Two things are true at once here and the split is deliberate. The **dashboard
still boots** — `cloop ui` is also how a single-project install runs, and
refusing to start it over a proxy certificate would be a poor exchange. But
**git workspaces stop**: a hub told to intercept does not quietly go back to
delivering the PAT, because a security control that disappears when it fails to
load is one nobody can rely on. The refusal carries
`executor.ErrWorkspaceUnavailable` and names the fix, and it is distinct from
the missing-grant refusal — "fix the proxy section" and "create a grant" send an
operator to different places.

Everything that is not a git workspace is unaffected: bind-mount executors,
non-git workloads and the whole UI keep working.

A related line, `ui: executor <id> is NOT routed through the git proxy: …`,
reports the same condition for one executor. `ui: git proxy decisions will go to
stderr, not the audit trail: …` is milder — the boundary still holds, the
evidence just is not in the database.

### Where it runs, and why there is no `cloop git-proxy`

The proxy is a background service of the hub process, started from
`bootstrapExecutors` (`pkg/ui/gitproxy.go`). There is no standalone command, and
that is a property of the design rather than an omission.

A session is minted at dispatch, in the driver, and authenticated minutes later
when the sandbox's git connects. Sessions live in a `gitproxy.Registry`, which is
memory — so **the process that mints must be the process that serves.** A
separate `cloop git-proxy` would authenticate against an empty registry and
refuse every request the hub had authorised. The alternative that would make one
work is a shared session store, which means the forge credential at rest in a
second place, for a topology nobody has asked for.

Two consequences follow from that:

- **It starts before any driver is given a credential source.** Reconciliation
  hands the Kubernetes driver its source once and that source is kept for the
  process's life, so a proxy started later would route the edge devices that
  connect afterwards and silently miss every Pod.
- **It is a process-wide singleton**, like the executor registry it feeds. Two
  `Server` instances in one process share one set of executors, so they must
  share the registry those executors' sandboxes authenticate against.

### The certificate the sandbox has to trust

The proxy's certificate is validated by **the sandbox's git**, not by the hub's
HTTP client. This is the deployment step most often missed, because everything on
the hub side works before it is done and the failure surfaces as a clone that
cannot verify the peer.

A certificate from a public CA needs nothing further. A self-signed or private-CA
certificate — the ordinary case for a `hub.internal` name — needs its CA in the
sandbox's trust store, which in practice means installing it in the sandbox
image. Alternatively, `pkg/executor/gitprovision` forwards `GIT_SSL_CAINFO`,
`GIT_SSL_CAPATH`, `SSL_CERT_FILE` and `SSL_CERT_DIR` from the machine git runs
on, so an operator who owns the image or the device can point at a bundle instead
of installing one. `GIT_SSL_NO_VERIFY` is deliberately not on that list:
disabling verification for a fetch carrying a brokered token is not a transport
preference, it is handing the token to whoever answers.

### `advertise_url`: what the sandbox can reach

`listen_addr` is where the proxy binds. `advertise_url` is what becomes the
sandbox's remote, and it has to resolve and route from *inside* the sandbox,
which is frequently not where the hub sees itself:

| Where git runs | `advertise_url` |
| --- | --- |
| Kubernetes Pod | the hub's Service — `https://cloop-hub.cloop.svc:8443` |
| enrolled edge device | whatever address the hub has on the link between them, and a certificate that covers it |
| a device sharing the hub's network namespace | may be omitted; the bound address is used, with an unspecified bind (`0.0.0.0`) read as `127.0.0.1` |
| inside docker on the hub's host | `https://host.docker.internal:8443` |
| inside podman on the hub's host | `https://host.containers.internal:8443` |

The first two rows are the ones that usually matter, because they are the only
two drivers that provision a git workspace at all. The container forms are here
for the case where the *agent* is itself containerised on the hub's host — the
`container` driver never clones, so it never reaches the proxy.

It must be `https`, must name a host, and must carry no path, query, fragment or
embedded credentials. The port is the one the sandbox reaches, which is the
published port rather than the bound one wherever a NAT sits in between.

Getting this wrong is not dangerous, only slow to diagnose: the sandbox's fetch
cannot connect, rather than a credential going somewhere it should not.

### What a dispatch does

No driver knows about the proxy. `pkg/executor/gitproxycreds` decorates the
`executor.WorkspaceCredentialSource` a driver was going to use anyway:

1. the inner source leases the forge credential from the broker, exactly as
   before;
2. that credential stays on the hub, and a session is minted against it;
3. the driver receives an `executor.WorkspaceAccess` — the session token plus
   `Minted.RepoURL` — and `Apply` rewrites the workspace's `Repo` for every git
   command that follows, the provisioning fetch and the write-back push alike.

Returning the URL *with* the credential is what makes the redirection hard to
skip: a driver that ignored `Repo` would send the sandbox at the forge holding a
token the forge has never heard of, which fails immediately instead of quietly
restoring the un-proxied path.

Two behaviours are worth naming.

**It fails closed.** If `Mint` fails, the dispatch fails: the inner lease is
released and the error names the repository. Falling back to the direct
credential would hand the sandbox the PAT precisely when the boundary is broken,
which is the one moment it must not — a proxy that fails open is not a boundary,
it is a default.

**A public repository passes through unproxied.** An empty credential is an
unauthenticated fetch; there is nothing to keep off the sandbox, so a session
would only add a hop that can fail.

The `ExpiresAt` the driver sees on the credential is the *session's*, not the
lease's. That is the deadline that now actually bounds the sandbox's access to
the forge — before interception the sandbox held the PAT and its access ended
never, whatever the lease said.

Every git-provisioning driver is routed, which is both of them: the Kubernetes
driver through `reconcile.Options.WrapWorkspaceSource`, and the remote agent
through the hub's per-executor credential factory. The `container` and
`localprocess` drivers bind the operator's own checkout and never clone, so there
is nothing on them to intercept.

The PAT itself is a `secretbroker` lease like any other — the change is where it
is *used*, not where it comes from. See
[GitHub repositories and PATs](guides/secrets.md#github-repositories-and-pats).

---

## Audit events

`Registry.OnEvent` receives every authorisation decision as an `Event`. Events
carry ids, ref names and reasons — no credential and no object content — so they
are safe to write to a log an operator reads. `Event.String()` renders one line.

| Kind | Emitted when | Notes |
| --- | --- | --- |
| `push_denied` | a push was refused by policy | **The row that matters.** It is the evidence that the boundary held, and the only place a sandbox's attempt to reach a protected branch is written down. Nothing else in cloop would record it. Alert on it. |
| `push_allowed` | every command in a push passed policy | Emitted *before* forwarding, so it describes what was **authorised**, not what the remote ultimately accepted. A `push_allowed` with no corresponding change on the forge means the forge refused it — branch protection, a non-fast-forward — not that the proxy did. |
| `session_minted` | a session was created | `Detail` carries the allowlist and the expiry. |
| `session_closed` | a session was revoked or reaped | `Detail` carries the reason and the session's push/fetch/denied counters. |
| `fetch` | a read went through the proxy | |
| `rejected` | a request was refused *before* policy ran | Unauthenticated, wrong repository, malformed pkt-lines, a route the proxy does not serve, or an upstream stream that ended early. Distinct from `push_denied`: nothing here got as far as a decision about a ref. |

`OnEvent` runs on the request goroutine. A handler that blocks blocks a push —
hand off to a queue if the sink can be slow. The hub's own sink does one insert
for that reason.

### Where they land

The hub forwards every event into the same hash-chained `audit_events` table as
the credential broker, with `entity_type` `gitproxy`, the session id as the
entity, and the event type prefixed: `gitproxy.push_denied`,
`gitproxy.push_allowed`, `gitproxy.session_minted`, `gitproxy.session_closed`,
`gitproxy.fetch`, `gitproxy.rejected`. The payload carries the session, the
repository, the project and task ids, the ref names and the reason — the same
fields `Event.String()` renders, and no others; `gitproxy.Event` has no field
that could hold credential material or object content, which is what makes the
table safe to export.

```console
$ cloop audit-log list --entity gitproxy --since 7d
$ cloop audit-log list --type gitproxy.push_denied --since 30d --json
```

An audit write that fails does not fail the push — but the decision has to be
visible somewhere, so it goes to stderr instead, prefixed `git-proxy:`. So does
every event on a hub whose database would not open.

A `push_denied` is not a false positive to be tuned away. Under this design a
well-behaved SDK-driven task never produces one, so every occurrence is either a
workload doing something it was not asked to do or a policy narrower than the
task it was minted for. Both are worth a human.

---

## Threat model notes

The standing assumption is unchanged from the
[threat model](security/threat-model.md): **the workload is hostile.** The
question is only what a leak is worth.

| Leaked | Worth |
| --- | --- |
| **Session token** | Exactly the policy, for the remaining TTL: push to `refs/heads/cloop/**`, create and update only, on **one** repository, through **one** proxy — plus the read of that one repository, since the hub's policy sets `AllowFetch` so the clone can go through the proxy as well. No deletes. No other repository the same proxy serves, because the session is pinned. Nothing at all against `github.com` directly — the token is meaningless there. |
| **PAT delivered into the sandbox** — what an un-configured hub still does | Every repository the token is scoped to, every ref in them, in every direction, from anywhere on the Internet, until someone notices and revokes it. |

Some sharper points:

- **Detection.** The token version leaves a `push_denied` row on the attempt.
  The PAT version leaves a force-push notification on the *success*.
- **Revocation.** `Registry.Close` cuts a session at the next request, with no
  forge round-trip and no coordination. Revoking a leaked PAT means an API call
  to GitHub and, usually, re-minting it for everything else that used it.
- **Blast radius of the proxy host.** The proxy is a process holding forge
  credentials for every live session. It must not run inside a sandbox, must not
  be reachable from anywhere the sandbox network is not, and its logs are as
  sensitive as its memory is — which is why events carry no material and errors
  are scrubbed. In the shipped topology that process is the **hub**, which
  already holds the sealing key and every stored credential, so this concentrates
  nothing that was not already concentrated. What it does add is a second
  listener on the hub, reachable by everything the sandbox network can reach:
  bind `listen_addr` as narrowly as that network allows.
- **Compromised proxy.** Nothing here defends against that; a compromised proxy
  is a compromised credential store. What it does buy over the status quo is
  that there is now exactly one such store to protect, instead of one per
  running sandbox.
- **What it still does not constrain.** The *content* of a push. A sandbox may
  write anything it likes to a branch it is allowed to write to. That is what
  `pkg/writeback`'s inspection is for — see
  [Result write-back](security/model.md#the-guarantee--test-table) — and the two
  are complementary: this proxy decides *where*, that one decides *what*.
- **Fast-forward and branch protection.** Still the forge's job, as above. A
  hub relying on this proxy alone has not protected `main` from history
  rewriting *within* the namespaces it did allow.

---

## See also

- [Security model](security/model.md) — the trust boundaries, the workspace
  credential's path, and the guarantee → test table
- [Threat model](security/threat-model.md) — STRIDE per boundary, with the
  honest residual-risk column
- [Executor architecture](architecture/executors.md) — where a sandbox comes
  from and how a work product gets back
- [Secret and egress grants](guides/secrets.md) — how the PAT the proxy holds is
  granted in the first place
- [Operator runbook](operations/runbook.md) — TLS material, rotation, and audit
  export
- [`pkg/gitproxy/proxy.go`](../pkg/gitproxy/proxy.go) — the package comment this
  document expands on
