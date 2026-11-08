# Git interception proxy

How cloop lets a sandbox push to some branches and not others, without giving it
a credential that could reach the others.

`pkg/gitproxy` is a git smart-HTTP proxy that runs outside the sandbox. The
sandbox's remote points at it, and the sandbox authenticates with a short-lived
session token. The proxy holds the real forge credential. For each push it
parses the list of ref updates, checks every update against the session's
policy, and only then presents the credential to the forge. So the branch
allowlist is enforced on the network path instead of relying on the sandbox to
respect it. The proxy also reads every push it allows on the way through, and
refuses one that carries a credential the run was given (see
[the push scan](#the-push-scan)).

The proxy runs inside the hub process and is off by default. A hub without it
behaves as [the hole it closes](#the-hole-it-closes) describes: the forge
credential is delivered into the sandbox, and only the sandbox's own code checks
the branch. Setting `executors.git_proxy.enabled: true` turns the proxy on. From
then on two kinds of git traffic go through it: every git workspace the hub
provisions, on Kubernetes Pods and enrolled edge devices alike, and the
sandbox's own git for every GitHub grant, whose token the hub then keeps. See
[operating it](#operating-it).

This page is the reference for what the proxy decides.
[Git proxy architecture](architecture/git-proxy.md) covers how it is wired into
the hub, the two paths a sandbox takes to reach it, what each executor backend
does to put a sandbox on them, and where that integration is still incomplete.

- [The hole it closes](#the-hole-it-closes)
- [The inversion](#the-inversion)
- [The policy model](#the-policy-model)
- [Session lifecycle](#session-lifecycle)
- [The push scan](#the-push-scan)
- [What it does not decide](#what-it-does-not-decide)
- [Operating it](#operating-it)
- [Audit events](#audit-events)
- [Threat model notes](#threat-model-notes)

---

## The hole it closes

With the proxy off, which is the default, the push write-back runs `git push`
inside the sandbox. `pkg/executor` requires every write-back branch to be under
`cloop/` (`executor.ValidateWriteBackBranch`), and `pkg/writeback` checks the
branch again when the result arrives. Both checks work, but a hostile sandbox
can get past either:

- `ValidateWriteBackBranch` runs inside `pkg/executor/gitwriteback`, which is
  code the sandbox itself runs: on the edge device through the remote agent, or
  as `cloop workspace writeback` inside the Pod. A workload can skip a check
  that it runs itself.
- `pkg/writeback` inspects the branch after it exists. With the push transport,
  the commit is already on the forge by the time anything on the hub looks at
  it. The hub can still refuse to merge it, but it can't undo the push.

The checks can't do more because of where the credential is. In push mode the
hub leases a GitHub credential (a `github_pat`, or an installation token minted
from a `github_app`) and delivers it into the sandbox, because that is where git
runs. It is delivered carefully, as a URL-scoped `http.<origin>.extraHeader` on
one git child process, never on disk and never in an argv (see
[Workspace provisioning](security/model.md#workspace-provisioning)). But once it
is delivered, the hub has no control over it. The sandbox holds a credential
that works for whole repositories, and is only expected to use part of that. A
workload that ignores the SDK and runs

```
git push --force origin HEAD:main
```

reaches `main`, and the first anyone hears of it is the force-push
notification. Nothing detects the attempt, because nothing on the hub is in the
path.

The normal write-back itself pushes with `--force` (the ref belongs to cloop, so
forcing it is correct). So the sandbox's git is already set up for the operation
you would least want it to aim at another branch.

Turning the proxy on doesn't remove either check. `ValidateWriteBackBranch` and
`pkg/writeback`'s inspection stay where they are. What changes is that they are
no longer the only thing between the sandbox and `main`, because the sandbox no
longer holds a credential that could reach it. Keeping both checks means a hub
with the proxy off, or a driver that doesn't route through it, still has them.

---

## The inversion

The proxy moves the authenticated part of git's traffic out of the sandbox:

```
sandbox ──session token──▶ gitproxy ──PAT──▶ github.com
                             │
                        Policy.Decide per ref
```

The sandbox's remote is rewritten to the proxy's URL for the session
(`Minted.RepoURL`, which carries no credential). The sandbox authenticates with
HTTP basic auth: the username is `Session.ID` and the password is the session
token. That token is useless anywhere else, for any other repository, and after
the TTL. The proxy holds the PAT, and `upstreamRequest` is the only place it is
attached. It is attached to a URL built from the session, not from anything in
the request, so a crafted request can't send the credential to a host of its
choosing.

The full request path:

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

Four more properties complete the design:

- **Byte-identical replay.** `ParseReceivePack` returns a reader that replays
  the command bytes it consumed, followed by the untouched pack. If the proxy
  re-encoded the command list from the parsed struct, the bytes the policy
  checked and the bytes the remote applies would come from different code, and
  any difference between them would be a bypass.
- **No redirects.** The client's `CheckRedirect` returns `http.ErrUseLastResponse`.
  Following a forge's 302 on a receive-pack would send the hub's credential to
  a host the session was never scoped to.
- **Upstream error bodies are not passed on.** For an upstream response of
  `>= 400`, the status is passed through so git reports something accurate, but
  the body is replaced with `cloop git proxy: upstream returned …`. A forge's
  error page can quote the request back, and the request carried the
  credential. For the same reason, every upstream header other than content
  type and encoding is dropped: a `Set-Cookie` or `WWW-Authenticate` header
  reaching the sandbox would leak the hub's session with the forge.
- **Errors are scrubbed.** `scrub` replaces the session's upstream password in
  any error text before it reaches the sandbox.

### How a refusal is reported

A denied push is reported in a form the client can read, based on the
capabilities it advertised on the first command line:

| Client asked for | What it gets |
| --- | --- |
| `report-status` or `report-status-v2` | HTTP 200 with a status report: `unpack ok` followed by one `ng <ref> <reason>` line per command. Git prints the reason next to the branch name and exits non-zero. |
| `report-status` **and** `side-band-64k` | The same report, plus the full explanation on side-band channel 2, which git prints with the prefix `remote:`. The `ng` reason is cut to one line, so this is where the whole sentence goes. |
| Neither | HTTP 403 with the reason as text. A client with no channel for a report can't be sent one, and a plain 200 would tell it that a push which moved nothing had succeeded. |

If any part of a push is refused, the whole push is refused. Commands that would
have passed on their own get
`ng … push refused as a whole because another ref was denied`. Applying part of
a push would let the sandbox map the allowlist by watching which of its commands
landed, and would leave the repository in a state neither side asked for.

---

## The policy model

`Policy` describes what one session may do to one repository's refs. Everything
is denied unless the policy allows it. An empty `AllowedRefs` means the built-in
write-back namespace, not "no restriction", and an unset `AllowDelete` means
deletes are refused. A permissive default here could let a sandbox force-push
over `main`, which is what the proxy exists to prevent, so no default trades
safety for convenience.

### Ref patterns

`AllowedRefs` are glob patterns matched against full ref names.

| Written | Means | Matches | Does not match |
| --- | --- | --- | --- |
| `cloop/*` | `refs/heads/cloop/*`: a bare name is read as a branch and gets `refs/heads/` in front | `refs/heads/cloop/task-42` | `refs/heads/cloop/task-42/fixup`, `refs/heads/main` |
| `refs/heads/cloop/*` | the same pattern, written out | as above | as above |
| `refs/heads/cloop/**` | any depth strictly below the prefix | `refs/heads/cloop/task-42`, `refs/heads/cloop/task-42/fixup` | `refs/heads/cloop` itself, because a namespace is where branches go, not a branch |
| `refs/tags/v*` | tags whose name has no further `/` | `refs/tags/v1.2.0` | `refs/tags/v1/2` |
| `refs/**` | everything | `refs/heads/main` | — |

Matching follows `path.Match`, so `*` does not cross a `/`. Keep this in mind
when you write an allowlist: `cloop/*` admits one level, and a per-task
namespace like `cloop/task-42/fixup` needs the `/**` form. The `/**` suffix is
handled as a prefix test before `path.Match` sees the pattern.

`Normalize()` fills in defaults, adds `refs/heads/` where needed and drops
duplicates. It is idempotent. `Validate()` then refuses a pattern that doesn't
start with `refs/`, contains `..` or `//`, ends with `/`, contains a control
character or a space, or doesn't compile as a glob. A pattern that doesn't
compile would match nothing, without an error, and look like a working allowlist
that denies everything. A whole-namespace pattern like `refs/**` is allowed: an
operator may want it, and refusing it here would only move the same decision
somewhere less visible. `MaxRefPatterns` (256) limits the list, because every
pattern is matched against every ref in every push, and without a limit an
attacker could choose how much work that is.

### Narrowing by grant: `RestrictRefs`

`RestrictRefs` is a second list of patterns, written and normalised like
`AllowedRefs`, that a ref must also match. It lets a grant narrow the hub's
allowlist without either list being rewritten. The operator's `allowed_refs`
stays the upper limit in `AllowedRefs`, and a grant's branch list (from
`cloop secret grant --branches`, or **Push to branches** on a project's
Repository Access panel) arrives as `RestrictRefs`.

| `AllowedRefs` (hub) | `RestrictRefs` (grant) | `refs/heads/main` | `refs/heads/cloop/fix-1` | `refs/heads/feature/x` |
| --- | --- | --- | --- | --- |
| `refs/heads/cloop/**` | — | refused | allowed | refused |
| `refs/heads/cloop/**` | `feature/*` | refused | refused | refused (the hub never allowed it) |
| `refs/heads/**` | `feature/*` | refused | refused | allowed |
| `refs/heads/**` | `cloop/*`, `main` | allowed | allowed | refused |

There are two lists that both have to match, instead of one list holding their
intersection, because the intersection of two sets of globs can't always be
written as a set of globs. `refs/heads/cloop/**` combined with
`refs/heads/*-hotfix` has no exact glob form, and an approximation would be
wrong in one direction or the other. Two lists are always exact.

Unlike `AllowedRefs`, an empty `RestrictRefs` gets no default: it means the
grant added no restriction. One case is refused: a list that had entries but
normalises to nothing, because every entry was blank, becomes a pattern that
`Validate()` rejects. So an unreadable restriction fails the session instead of
being dropped. `RestrictRefs` makes a policy non-zero, so `Mint` never replaces
a policy that only narrows with `WriteBackPolicy()`.

Both kinds of session are narrowed this way: the lease session a sandbox
receives (`pkg/ui` `guardPolicy`, which also removes create and update for a
grant that can't push, and never grants a delete), and the workspace session
that cloop's own provisioning and write-back use (`pkg/executor/gitproxycreds`,
from the branch list the grant's credential carries). A read-only session
carries no restriction, since it has no push to narrow.

### Directions

A ref update is a create, an update or a delete, depending on which side is the
all-zero object name. Each is a separate permission:

| Field | Grants | Default | Why |
| --- | --- | --- | --- |
| `AllowCreate` | creating an allowed ref | off | The normal write-back case, and the permission a caller almost always wants. |
| `AllowUpdate` | moving an existing allowed ref to a new commit | off | A retried task replaces the branch its earlier attempt pushed. |
| `AllowDelete` | removing an allowed ref | off | A write-back never needs it, and an allowlist of names that ignored deletes would let a sandbox delete the branches it was scoped to. |
| `AllowFetch` | reading (`git-upload-pack`) over the same session | off | A sandbox that clones through the proxy needs it. One that only pushes back a tree it was given doesn't. |

`Validate()` refuses a policy with all four off. A policy that permits nothing
almost always comes from a caller that built a `Policy{}` and expected defaults,
and an error is more useful than a session that refuses every request.

### Ceilings

| Field | Default | Bounds |
| --- | --- | --- |
| `MaxCommands` | `DefaultMaxCommands` = 16 | Ref updates in one push. A write-back moves one branch, so anything past a handful is a mirror push or a search for a ref the allowlist missed. |
| `MaxPackBytes` | `DefaultMaxPackBytes` = 2 GiB | The request body. The pack is streamed, not buffered, so this isn't a memory limit. It limits how much one session can push through the hub's credential in one request. |

The command section is capped separately at 1 MiB before any of it is parsed,
because the proxy has to hold those bytes in memory to make its decision.

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

This is the executor write-back path as a policy: create and update inside the
`cloop/` namespace, no deletes, no fetch. `DefaultAllowedRef` is built from
`executor.WriteBackBranchPrefix`, so the proxy's allowlist and the check inside
the sandbox can't drift apart. The difference is that the proxy enforces the
prefix from outside the sandbox.

It is a constructor because every caller that set these four booleans by hand
could get one wrong, and three of the four mistakes would go unnoticed. `Mint`
applies it when the request's policy is entirely zero-valued (`Policy.IsZero()`),
which means nobody filled the policy in. A policy someone wrote to permit nothing
is different: that is a `Validate()` error, and replacing it with a default would
widen a policy an operator meant to be narrow.

The hub's own policy is this plus fetch. `GitProxyConfig.Policy()` always sets
`AllowFetch`, because with the proxy in place the provisioning clone goes through
it too. If sandboxes still fetched directly, the hub would still be delivering
the PAT, and the proxy would cover only half the round trip. The rest comes from
configuration: `allowed_refs` is the allowlist (empty means
`refs/heads/cloop/**`), `allow_delete` is the one direction an operator can add,
and create and update are always on, because a write-back needs both.

### Deciding a push

`Policy.Decide` checks the name first, then the direction. A sandbox probing for
a ref learns the same either way, but an operator reading the audit
trail wants `main is not in the allowlist` rather than `delete is not
permitted`, because the first names the real problem. `DecideAll` evaluates
every command and reports whether all of them passed. Each refusal's text is
carried on a `Decision` and rendered as a single line, since git's status report
is newline-delimited and a multi-line message would be split into a status line
and garbage.

The name check tests the hub's limit first, then the grant. The two refusals are
worded differently because they are fixed in different places. A ref outside
`AllowedRefs` gets `not in this session's branch allowlist (…)`, which is the
operator's decision. A ref inside it but outside `RestrictRefs` gets
`outside the branches this session's grant may push to (…)`, which is the
project's. Both carry the reason code `ref_not_allowed`, so the metric isn't
split. The reason git prints lists the patterns that would have been accepted.
It doesn't repeat the ref, which the status line already shows next to it, so
that a long branch name can't push the list past the one-line cut.
(`RefDenial.Error()` still names the ref, for anything that logs it on its own.)

Before the policy runs, each parsed command must pass `ValidateRefName`, which
applies git's own naming rules. The proxy forwards this string to a real git
server, so a name git would refuse is refused here instead of being passed
along. That keeps names like `refs/heads/../../x` and
`refs/heads/ --upload-pack=sh` out of the policy code. An update from the zero
SHA to the zero SHA is refused too: it is harmless upstream, but it isn't a
create, an update or a delete.

The object names in a command are not verified. `Old` is the client's claim
about what the remote currently holds. The remote checks it, the proxy doesn't,
and no decision here depends on it being true. The proxy relies only on which
side is zero, because that is what tells a create, an update and a delete apart.

---

## Session lifecycle

A session is one sandbox's brokered access to a repository (or, when it carries
an allowlist, to a set of them) for one TTL, under one policy. See
[Scoped sessions](#scoped-sessions-an-allowlist-instead-of-one-repository).

### Minting

`Registry.Mint(MintRequest)` takes the upstream `https://` URL, the `Credential`
to present there, the `Policy`, a TTL, and audit labels (`ProjectID`, `TaskID`,
`ExecutorID`, `Actor`). It returns a `Minted`:

| Field | What it is |
| --- | --- |
| `Session` | the live session; `Session.ID` is the basic-auth username and is not secret |
| `Token` | the plaintext session token. This is the only copy: the registry keeps `sha256(token)` and nothing else |
| `RepoURL` | what the sandbox sets as its remote: the proxy's base URL plus `owner/name`. Carries no credential |

`Minted.Credential()` returns the pair a driver delivers into the sandbox.

By default the repository is **pinned** when the session is minted.
`UpstreamRepoPath` parses `owner/name` out of the upstream URL, and requires
`https`, a host and no embedded credentials. The session is served under that
path, and every request is compared against it. The `owner/name` shape matters:
`executor.Workspace`'s `RepoPath` parses the same thing out of a clone URL to
match a GitHub grant's repository allowlist, so a proxy URL that didn't keep it
would break grant matching for every workspace routed through the proxy.

### Scoped sessions: an allowlist instead of one repository

Pinning works for workspace write-back, where the hub knows the repository
before it dispatches. It doesn't work for a user's GitHub PAT, which is granted
to a project with an allowlist like `acme/*`. That set lives on GitHub, changes
without notice, and neither the user nor the hub can list it at mint time.

Setting `MintRequest.RepoPatterns` mints a *scoped* session instead, which
carries the allowlist and checks each request against it. `Upstream` then has to
be a bare forge host base (`https://github.com`). `UpstreamHostBase` validates
it with the opposite rule to `UpstreamRepoPath`: there must be no path, because
on a scoped session every path segment comes from the request, and a path in
the base would be put in front of all of them without any error.

| | Pinned | Scoped |
| --- | --- | --- |
| `MintRequest.Upstream` | the repository URL | the forge host base |
| `Session.RepoPath` | `owner/name` | empty |
| `Session.RepoPatterns` | empty | the allowlist |
| `Minted.RepoURL` | proxy base + `owner/name` | the proxy base alone |
| Admits | exactly that repository | whatever the allowlist matches |

`Minted.RepoURL` differs because there is no single repository to name. The
sandbox gets a base URL that `url.<base>.insteadOf` rewrites
`https://github.com/` to, and the repository comes from whatever it was already
trying to clone. [The secrets guide](guides/secrets.md#the-helpers-limit-and-what-removes-it)
shows what that looks like in a lease directory.

**Matching.** Patterns are `owner/name` globs. They are normalised to lowercase,
with any `.git` suffix and surrounding slashes removed, and matched with
`path.Match`, so `*` doesn't cross a `/`: `acme/*` admits `acme/tool` but not
`acme/group/tool`. Patterns are deduplicated at mint time and capped at
`MaxRepoPatterns` (64). An empty or malformed allowlist is an error, not a
session that admits everything or nothing.

**Allowed characters.** Both segments must match `[A-Za-z0-9._-]`, be no longer
than 100 characters, and not contain `..`. `secretbroker.validRepoSegment`
applies the same rule on the grant side, so the two can't disagree about what
can be named.

This matters because `AllowsRepo` matches a string, and that string is then
built into a URL that `net/http` parses again on the way to the forge. Any
character that survives matching and changes meaning in the second parse makes
the approved path and the forwarded path different. This is the escape the rule
closes, which an earlier version of the proxy had:

```
sandbox: GET /acme/..%252F..%252Fsomebody-else%252Fprivate/info/refs
         → reaches the proxy as the literal text "..%2F..%2Fsomebody-else%2Fprivate"
         → contains no separator, so it passes the one-slash check
         → matches "acme/*"
         → the forge decodes %2F back into "/" and serves a denied repository
```

`%3F` and `%23` do the same with `?` and `#`: the second parse cuts the path
short, so the forge sees only a prefix of what was matched. Allowing only the
characters a forge permits in a repository name makes the matched string and the
forwarded string identical.

**A name that still ends in `.git` after normalising is refused too.** It is the
same defect arriving another way. `.git` is stripped in three places
(`splitGitPath`, `NormalizeRepoPath`, and again where the upstream URL is
assembled), but approval happens after the second:

```
sandbox: GET /acme/tool.git.git.git/info/refs
         splitGitPath      → acme/tool.git.git
         NormalizeRepoPath → acme/tool.git      ← approved against the allowlist
         upstream assembly → acme/tool          ← what the forge is asked for
```

With an allowlist of `acme/tool.*`, the first is admitted and the second is
denied, so without this check the sandbox could read, and push to, a repository
it was refused. The underlying fault was that `NormalizeRepoPath` wasn't
idempotent, while the code between check and forward assumed it was. Refusing
the input that makes it non-idempotent restores that assumption.
`acme/tool.git` itself is unaffected: it is the normal form a git client sends,
and it normalises to `acme/tool`.

**What the tests check.** `TestNormalizeIsIdempotentForEverythingAdmitted`
checks the property itself: anything `AllowsRepo` admits normalises to a fixed
point. So a future normalisation step that isn't idempotent fails the test
instead of shipping as a third bypass.
`TestAllowsRepoRejectsPathsThatChangeMeaningWhenReparsed` covers the concrete
cases, including both bypasses above as regression tests.

**What scoping doesn't change.** The credential is still only presented to the
host the session names. `Session.upstreamFor` builds the upstream URL from the
session's own base plus the request's path, and runs `AllowsRepo` again instead
of trusting that `ServeHTTP` already did. The check and the URL construction are
in one function so that a later edit can't separate them. Nothing in a request
can change which host the token reaches.

TTLs:

| Constant | Value | Meaning |
| --- | --- | --- |
| `DefaultSessionTTL` | 1 hour | Used when `MintRequest.TTL` is zero. It covers a task's git traffic, not the whole task: the clone and the write-back push both happen inside it. An hour is enough for a slow clone of a large repository over a slow link, and still expires long before a leaked token could be used at leisure. |
| `MaxSessionTTL` | 12 hours | The upper limit. A long-lived git proxy session is no different from handing the sandbox the credential itself. |

A TTL above `MaxSessionTTL` is an error. It isn't reduced to the limit, because a
caller that asked for a day and got twelve hours would only find out when a
push failed halfway through.

### Authenticating

`Registry.Authenticate(id, token)` always hashes the presented token, so an
unknown session id costs the same as a known one with a wrong token, and
compares with `subtle.ConstantTimeCompare`. An unknown session, a wrong token, a
revoked session and an expired one all return `ErrUnauthenticated`. They share
one error so that a caller can't tell "no such session" from "wrong token" and
use the difference to discover session ids. `ErrSessionNotFound` exists
separately for management calls, where the caller is the operator and needs the
exact reason.

The hub's session TTL is `executors.git_proxy.session_minutes`, which defaults
to 60 (the same hour as `DefaultSessionTTL`). It is also the period by which a
workspace session is renewed. A value outside
`[0, GitProxySessionMinutesUpper]` (720, which is `MaxSessionTTL`) is reported
and reset to the default when the configuration loads, instead of being
clamped to the limit.

A session's TTL and the life of its upstream credential are separate. A GitHub
App installation token is valid for an hour. A session presenting one renews it
through the broker when about ten minutes are left, at the scope it was first
minted at, and destroys the old token once no request is still using it. So a
session set to last three hours keeps working at GitHub for three hours. If the
broker or GitHub refuses a renewal (because the grant was revoked or the
installation suspended), the session is closed. See
[the upstream credential renews itself](architecture/git-proxy.md#the-upstream-credential-renews-itself).

### A workspace session lives as long as its run

This section is about the workspace session, the one cloop's own fetch and
write-back use. A session minted for a GitHub lease ends with its lease, or
`session_minutes` after dispatch; see [closing and reaping](#closing-and-reaping).

The credential source mints the session at dispatch. The sandbox fetches at the
start of a run and pushes at the end, so the session has to last from one to the
other, and no longer:

- **It ends when the run is done with it.** For a run that pushes nothing back,
  the driver hands the credential back after the fetch. For a run that does, it
  hands it back once the workload has finished and its write-back has run or
  been abandoned. (The remote driver keeps the release on the run's handle, and
  the Kubernetes driver keeps it with the workspace Secret.) Handing it back
  closes the session, with the reason *"the run is done with its workspace
  credential"*, or *"workspace credential released unused"* if nothing ever
  presented it, and releases the lease behind it. If the hub that dispatched
  the run stops first, the member that adopts the run restores the session and
  ends it when the dispatcher would have: with the workload for a device's push
  write-back, and for a Pod once its init container's fetch is confirmed, or
  with the workload under `write_back: push`.
- **It is renewed while the run lives.** It is minted for `session_minutes` and
  extended by another `session_minutes` whenever five minutes or less are left
  (half a period, for a period under ten minutes). The dispatching hub renews it
  while its driver still holds the credential. After a restart, the member that
  adopted the run renews it while the workload is still running. Each renewal is
  written to the session's record, so it survives a restart, and audited as
  [`gitproxy.session_renewed`](reference/audit-events.md#gitproxy). The sandbox
  isn't given a deadline, because the device would refuse to push after it. The
  proxy is what refuses a session that has lapsed.

So `session_minutes` doesn't limit how long a run may take. It limits how long a
session stays valid once nothing renews it. A run that ends early doesn't leave
its session valid for the rest of the hour (or of the twelve) for anything that
copied its token out of the sandbox. A member on an older build restores only
sessions still within their first period. If such a member adopts a run whose
session was renewed past that, the run's write-back push gets HTTP 401, which
the sandbox's git reports as an authentication failure and the audit trail
records as a `rejected` event.

### Closing and reaping

`Registry.Close(id, reason)` revokes a session. It is idempotent, so a caller
can call it from a `defer` without checking whether the run has already ended.
The closing audit row carries the session's counters. The next request is
refused, with no round trip to the forge and no coordination.

No command calls it directly. A workspace session's lease, though, is listed
with the hub's other leases and kept alive as long as the session lives, and
revoking it in the Secrets panel (or with `POST /api/leases/{id}/revoke`) closes
the session at once. A hub restart suspends a recorded session instead of
closing it, and the process that adopts its run restores it. Otherwise a session
ends with its run, or lapses once nothing renews it, which authentication
enforces whether or not the reaper has removed it yet. Revoking the underlying
grant with `cloop secret revoke` stops the next dispatch from minting anything,
and also closes the sessions the grant fed (see
[revoking a grant](guides/secrets.md#revoking-a-grant)).

**Guarded GitHub sessions** (the scoped sessions that `github_pat` and
`github_app` leases mint) are the exception: each is closed when the lease that
created it is released. Wiping the lease directory removes the session token
from the sandbox, but a workload that copied it out first would otherwise keep
PAT-backed access to the whole allowlist until the TTL ran out: up to an hour by
default, after the task and any revocation by the operator. The session id is
passed in the material's environment as `CLOOP_GIT_PROXY_SESSION` (it isn't
secret; the token is in a separate 0600 file). That is how `secretLease.Close`
finds the sessions to end without the broker having to know what a proxy
session is.

A lease is released when its workload ends, when an operator revokes it, and
when it lapses. A run's lease is issued for at most 15 minutes and extended in
place while its run is live, so it lapses only when the run is gone or one of
its grants was revoked or expired. The lease janitor then removes it within a
minute and closes its sessions. So a guarded session ends at its lease's release
or after its own `session_minutes`, whichever comes first. See
[how long a session lives](architecture/git-proxy.md#how-long-a-session-lives).

`Registry.ReapExpired()` removes sessions past their TTL and returns how many it
removed. `Authenticate` already refuses an expired session, so this only keeps
the map from growing for the life of the process. The hub runs it every 5
minutes, so a lapsed entry stays in memory for at most that long.

When the hub shuts down, it closes every live session with the reason *"the hub
is shutting down"*, so the audit trail records why they ended and their counters
are kept in the closing rows.

`Session.Stats()` returns `Pushes`, `Fetches`, `Denied`, `BytesUp` and
`BytesDown`. Operators see the first three in the `Detail` of a
`gitproxy.session_closed` row. The byte counters are only visible through
`Stats()`. `BytesDown` counts the bytes streamed back to the sandbox. `BytesUp`
is never incremented and always reads zero, so it doesn't tell you whether
anything was pushed.

---

## The push scan

A workload holds its leased credentials in plaintext, and a push that contains
one publishes it, possibly to a public repository. GitHub's push protection,
where enabled, recognises known token formats, but an internal API key granted
as an env secret matches none of them. So every push the policy allows is
scanned on its way to the forge:

- **What it looks for.** The values the hub delivered to the session's run: env
  values, a kubeconfig's bearer tokens and client keys, registry auth, egress
  proxy credentials and the run's egress and model relay session tokens, the
  git proxy session token a GitHub lease delivered, and also the PAT or App
  token the proxy presents upstream. Each is matched as delivered, base64-encoded
  (both alphabets, every alignment) and percent-encoded. Nothing shorter than
  eight bytes is matched. `push_scan: shapes` adds pkg/redact's registry of
  credential formats.
- **Where.** Every object in the pack (commits, trees, blobs, tags, and the
  bytes each delta inserts), plus the ref names and push options.
- **When.** While the pack streams through. The proxy inflates the pack as it
  forwards it and holds back the trailing checksum until the scan ends. A clean
  push reaches the forge byte for byte. For a refused push, the request to the
  forge is abandoned partway through the body, so receive-pack never has a whole
  pack and no ref moves.
- **What the sandbox sees.** Its git prints the refusal: each object, its path
  where a tree in the pack names it, its commit, and the grant and secret the
  value came from (never the value), and `! [remote rejected]` against every
  ref. The same goes into a `gitproxy.push_secret_refused` audit row, a
  `git_push_refused` row in the run's history, and a line in the task's details.
- **Limits.** `push_scan_max_object_mb`, `push_scan_max_push_mb` and
  `push_scan_seconds` limit what one push's scan may cost. A push past a limit,
  or a pack the proxy can't read, is refused with an error naming the limit or
  the fault. A scan that gave up doesn't count as a scan that found nothing.

```yaml
executors:
  git_proxy:
    enabled: true
    tls: auto
    push_scan: values           # the default; shapes adds credential formats; off forwards unread
    push_scan_max_object_mb: 1024
    push_scan_max_push_mb: 4096
    push_scan_seconds: 300
```

A project's own `.cloop/config.yaml` may set a stricter `push_scan` for its
pushes, but not a weaker one.
[Git proxy architecture](architecture/git-proxy.md#the-push-scan) covers the
design, the pack reader, measurements on a 100 MiB pack, and what the scan
can't see: a value split across a delta's copy and insert, a value transformed
in a way the scan doesn't decode, and, after a hub restart, a session token
minted before its kind carried a prefix.

---

## What it does not decide

The proxy doesn't do these three things:

### Whether an update is a fast-forward

Deciding that needs the object graph (whether the old commit is an ancestor of
the new one), which the proxy doesn't have and would have to index a pack to
get. Enforce fast-forwards on the forge, which has the graph: GitHub branch
protection, or `receive.denyNonFastForwards` on a self-hosted remote.

The proxy enforces which refs a sandbox may touch and in which direction
(create, update, delete), which is what stops a sandbox reaching a branch a
person owns. It doesn't refuse history rewriting inside the sandbox's own
namespace, and the write-back path wouldn't want it to: the normal write-back
force-updates its own branch.

### Signed pushes

A push that carries a push certificate is refused with HTTP 403. With
`push-cert`, the command list is inside a signed block and the remote applies
that copy, so checking the allowlist against the unsigned lines would check
bytes nothing acts on. Without full certificate parsing and verification,
refusing is the only safe option. Passing such pushes through would give the
branch allowlist a known bypass.

### Filtering the ref advertisement

`GET /info/refs` is forwarded unchanged. Trimming it to the allowed refs would
backfire: a receive-pack client treats every advertised ref as an object the
remote already has and so doesn't need to send. With `refs/heads/main` hidden,
the sandbox would re-send the entire history reachable from it on every push: a
pack of hundreds of megabytes where a few kilobytes were needed, over a link the
hub pays for, again and again.

The allowlist is enforced on the command list instead, where it costs nothing
and a client that skips discovery can't get around it. Hiding the ref names
wouldn't add security anyway: a sandbox that can read its checkout already
knows them.

The advertisement is gated only on the broad question. A session whose policy
permits no write can't ask for the `git-receive-pack` advertisement, and one
without `AllowFetch` can't ask for `git-upload-pack`. A request with no
`service` parameter is the dumb protocol and is refused, which keeps the proxy
to the three routes above.

---

## Operating it

### TLS is not optional

`Registry.BaseURL` must be `https` and have a host, and must have no path,
query, fragment or embedded credentials. `NewRegistry` and `New` both refuse
anything else.

This protects the token. The sandbox sends it in an `Authorization` header on
every request, and over cleartext anyone on the path could read it. That
includes a loopback proxy: a sandbox may share its host with anything else
listening on loopback, which is the reason for running workloads in sandboxes.

`Proxy.Serve(ln)` takes a listener instead of a certificate path, so the caller
configures TLS through [`pkg/tlsconf`](../pkg/tlsconf/tlsconf.go) as the hub
does and passes in a TLS listener. The hub builds it from `cert_file`,
`key_file` and `min_tls_version`, or, under `tls: auto`, with a certificate it
issues itself and picks per handshake ([`pkg/hubca`](../pkg/hubca/hubca.go)).
`Options.Transport` covers the connection to the forge: an operator whose forge
is behind a private CA supplies a `RoundTripper`, so the package needs no flag
that weakens the default.

An enabled section with neither `tls: auto` nor both `cert_file` and `key_file`
doesn't start a cleartext proxy. It is reported and switched off at load.
`tls: auto` is never assumed because the files are missing: a section with
`enabled: true` and no files has always been switched off, and upgrading to a
build with `tls: auto` shouldn't start a proxy for it. Switching off is safe because with the proxy off, a
workspace is provisioned the way it was before the proxy existed, which is
documented behaviour.

Timeouts are set where a stall would be a bug, and left off where waiting is
normal: 15 s to dial the forge, 60 s for it to start replying, 30 s to read
request headers, 2 min idle, and 30 s of grace for requests in flight on
`Close`. There is no overall client timeout and no `WriteTimeout`, because
cloning or pushing a large repository can take longer than any sensible limit,
and the request context ends anyway when the peer hangs up.

### Turning it on

Add one section to the hub's `.cloop/config.yaml`. If two dashboards share a
working directory, put it in the overlay of the hub that should run the proxy,
`.cloop/config.ui-<port>.yaml`, so the other dashboard isn't affected (see
[two dashboards in one directory](reference/configuration.md#two-dashboards-in-one-directory)):

```yaml
executors:
  git_proxy:
    enabled: true
    tls: auto                                      # the hub issues the certificate
    listen_addr: "0.0.0.0:8443"                    # where the proxy binds
    advertise_url: "https://hub.internal:8443"     # what the SANDBOX connects to
    min_tls_version: "1.2"                         # or "1.3"; empty means 1.2
    session_minutes: 60                            # 0 means 60; ceiling is 720
    allowed_refs: ["refs/heads/cloop/**"]          # the default; widen deliberately
    allow_delete: false
```

`cloop hub bootstrap` writes this section, and the Kubernetes monitor's, with
`advertise_url` on the host of `--external-url`. `enabled` and the certificate
source (`tls: auto`, or `cert_file` and `key_file` with your own pair) are the
only keys with no useful default. `tls: auto` needs `CLOOP_SECRET_KEY`, which
the hub's CA is sealed under; see
[the certificate the sandbox has to trust](#the-certificate-the-sandbox-has-to-trust).
An empty `listen_addr` binds an ephemeral loopback port, and an empty
`advertise_url` falls back to the bound address. That pair only works when the
sandbox shares the hub's network namespace.

The section is validated when it is loaded. `allowed_refs` goes through the same
`Normalize()` and `Validate()` the proxy enforces with, so a pattern that would
match nothing is refused when it is written, instead of looking like a working
allowlist that denies everything. A rejected list is reset as a whole to the
built-in namespace, because a partly applied allowlist is a policy nobody wrote.
The same goes for `session_minutes`, `min_tls_version`, `listen_addr` and
`advertise_url`. Three problems would leave an unusable or unsafe proxy (a
listen address nobody chose, an advertise URL a sandbox would send a token to in
cleartext, and missing TLS material), so they switch `enabled` off instead.

A hub that started the proxy logs it once, with the bind address, the URL
sandboxes will be pointed at and the allowlist in force, and, under
`tls: auto`, the certificate it serves:

```
ui: git interception proxy on 0.0.0.0:8443, advertised as https://hub.internal:8443; pushes limited to refs/heads/cloop/**
ui: git proxy serves a certificate the hub issued (tls: auto) for hub.internal, valid until 2026-10-14T09:12:40Z; sandboxes are told to trust the hub CA for https://hub.internal:8443 only
```

A hub that couldn't start the proxy still starts, and logs what isn't in effect:

```
ui: git interception proxy NOT started: git proxy listen on 0.0.0.0:8443: bind: address already in use
    executors.git_proxy is enabled, so no git workspace can be provisioned:
    dispatches needing one will be refused rather than handed the forge
    credential directly. Fix the section or set enabled: false.
```

The dashboard still starts, because `cloop ui` is also how a single-project
install runs, and refusing to start it over a proxy certificate would cost too
much. But git workspaces stop. A hub configured to intercept doesn't go back to
delivering the PAT, because nobody can rely on a security control that
disappears when it fails to load. The error carries
`executor.ErrWorkspaceUnavailable` and names the fix. It differs from the
missing-grant error, because "fix the proxy section" and "create a grant" send
an operator to different places.

Everything that isn't a git workspace is unaffected: bind-mount executors,
non-git workloads and the whole UI keep working.

A related line, `ui: executor <id> is NOT routed through the git proxy: …`,
reports the same condition for one executor. `ui: git proxy decisions will go to
stderr, not the audit trail: …` is less serious: the proxy still enforces its
policy, but the record of its decisions isn't in the database.

### Where it runs, and why there is no `cloop git-proxy`

The proxy is a background service of the hub process, started from
`bootstrapExecutors` (`pkg/ui/gitproxy.go`). There is no standalone command, for
the reasons below.

A session is minted at dispatch, in the driver, and authenticated minutes later
when the sandbox's git connects. Sessions live in a `gitproxy.Registry` in
memory, so the process that mints a session has to be the one that serves it. A
separate `cloop git-proxy` would authenticate against an empty registry and
refuse every request the hub had authorised. Making that work would need a
shared store of what a session presents, which means keeping the forge
credential in a second place, for a setup nobody has asked for. The hub does
record a session's id, token hash and scope. None of that authenticates or is
presented upstream, but it lets the hub process that adopts a run after this one
stops restore the run's sessions, deriving their credentials again from the
run's lease; see
[a hub restarted mid-run](architecture/git-proxy.md#a-hub-restarted-mid-run).

Two things follow from this:

- **It starts before any driver is given a credential source.** Reconciliation
  gives the Kubernetes driver its source once, and the driver keeps it for the
  life of the process. A proxy started later would route the edge devices that
  connect afterwards, but miss every Pod without an error.
- **It is a process-wide singleton**, like the executor registry it feeds. Two
  `Server` instances in one process share one set of executors, so they have to
  share the registry those executors' sandboxes authenticate against.

### The certificate the sandbox has to trust

The proxy's certificate is checked by the sandbox's git, not by the hub's HTTP
client. This used to be the deployment step most often missed, because
everything on the hub side works without it and the failure shows up as a clone
that can't verify the peer. `tls: auto` takes care of it.

**Under `tls: auto` the hub is the CA, and tells every sandbox to trust it.**
The CA is minted once per control plane, by whichever hub process first starts a
monitor under `tls: auto` (another process starting at the same moment adopts it
instead of minting a second). Its private key is sealed under the KEK registry
in the control-plane database (`hub_tls`) and never written to a file. So every
[hub-cluster member](architecture/hub-cluster.md) serves the same identity, a
database backup includes it, `cloop hub key rotate` rewraps it, and key
retirement counts it.

The proxy serves a leaf certificate from the CA for the host of `advertise_url`
and of a specific `listen_addr`, valid for 72 hours. The cluster leader replaces
the leaf when 48 hours are left, and every member re-reads it each minute and
serves it per handshake, so nothing is interrupted: a push in flight keeps its
connection, and the next one verifies the new leaf against the same CA. The CA
itself is replaced online, in stages, so that every sandbox trusts the new CA
before any certificate comes from it: `cloop hub ca rotate --stage`, then
`--activate` once no run dispatched before the stage is still running, then
`--retire-previous`, or `--now` in an emergency. See
[Rotating the hub CA](operations/runbook.md#rotating-the-hub-ca).

Each dispatch carries the CA's certificate (`executor.Spec.GitCA`, which is
public), and each driver makes the workload trust it for the proxy's URL and
nothing else. It uses `http.<advertise_url>.sslCAInfo`, added to the
`GIT_CONFIG_COUNT` block git reads from the environment, and never
`GIT_SSL_CAINFO`:

| Sandbox | Where the CA lands |
| --- | --- |
| host process (`localprocess`) | a file in a private directory of the run's own, removed when it ends |
| container | `/etc/cloop/hub-ca/ca.crt`, bind-mounted read-only |
| Pod | the run's lease Secret, projected read-only at `/etc/cloop/hub-ca/ca.crt` in the harness and in the workspace provisioner, unless `executors.kubernetes.git_ca_bundle` already names the proxy's URL |
| edge device, host or container mode, and its virtual executors | the start frame's Spec. The agent's provisioning fetch and write-back push trust it, and its inner driver places it as above. Needs protocol v21 or later: an older agent is refused a workload that would talk to the proxy, with an error naming the upgrade, and is never sent the forge credential instead |

Scoping the trust to the proxy's URL matters. `GIT_SSL_CAINFO` would replace the
image's trust store, breaking every other host the workload reaches, and would
trust any server whose certificate the hub's CA signed, such as the Kubernetes
monitor's. With the setting scoped, a second https server holding a leaf from
the same CA is checked against the image's own store and refused.
`TestContainerGitTrustsTheHubCAForTheProxyOnly` tests this in a real container,
`TestLoopbackDeviceTrustsTheHubCAForTheProxyOnly` through a real agent, and
[`tests/kube`](../tests/kube/README.md) in a Pod. The CA's private key never
reaches a sandbox or an agent: `GitCA` refuses any PEM block that isn't a
certificate.

**With `cert_file` and `key_file`, you are the CA.** A certificate from a public
CA needs nothing more. A self-signed or private-CA certificate needs its CA in
the sandbox's trust store, which in practice means installing it in the sandbox
image. Alternatively, `pkg/executor/gitprovision` forwards `GIT_SSL_CAINFO`,
`GIT_SSL_CAPATH`, `SSL_CERT_FILE` and `SSL_CERT_DIR` from the machine git runs
on, so an operator who controls the image or the device can point at a bundle
instead. `GIT_SSL_NO_VERIFY` is not forwarded: turning off verification for a
fetch that carries a brokered token would hand the token to whoever answers.

A Pod gives the operator neither option, because the Kubernetes driver writes
its spec, and a proxy served under an in-cluster Service name has a certificate
no public CA issued. So the driver handles it.
[`executors.kubernetes.git_ca_bundle`](reference/configuration.md#on-kubernetes-the-git-proxys-ca-for-its-url-only)
names a ConfigMap in the workload namespace and the proxy's URL. Every Pod mounts
the CA at `/etc/cloop/git-ca/ca.crt` and trusts it as `http.<url>.sslCAInfo`,
for that URL only, so every other host keeps the image's own store. The
provisioning fetch and the write-back push, which run with a closed environment,
import those keys and nothing else from it (`gitprovision.TransportConfig`). The
Helm chart renders both the section and the ConfigMap; see
[deploy/README.md](../deploy/README.md#the-git-proxy-and-the-kubernetes-access-monitor).

### `advertise_url`: what the sandbox can reach

`listen_addr` is where the proxy binds. `advertise_url` becomes the sandbox's
remote, so it has to resolve and be reachable from inside the sandbox, which
often isn't the address the hub sees for itself:

| Where git runs | `advertise_url` |
| --- | --- |
| Kubernetes Pod | the hub's Service, for example `https://cloop-hub.cloop.svc:8443` |
| enrolled edge device | whatever address the hub has on the link between them, and a certificate that covers it |
| a device sharing the hub's network namespace | may be omitted; the bound address is used, with an unspecified bind (`0.0.0.0`) read as `127.0.0.1` |
| inside docker on the hub's host | `https://host.docker.internal:8443` |
| inside podman on the hub's host | `https://host.containers.internal:8443` |

The first two rows are the only two drivers that provision a git workspace, so
cloop's own fetch uses them. Other sandboxes reach the proxy too: every sandbox
holding a GitHub grant sends its own git there. That includes a `container`
sandbox on the hub's host, which never clones a workspace but clones whatever
its workload asks for, and a container on an edge device, whose route out is the
device's container network and firewall, not the device's own. The container
rows are for those. A route also has to exist: the `container` driver's default
network is `none`, and nothing cloop generates (no firewall, egress filter or
`NetworkPolicy`) admits the proxy's address by itself. See
[the network between sandbox and proxy](architecture/git-proxy.md#the-network-between-sandbox-and-proxy).

It must be `https`, must name a host, and must have no path, query, fragment or
embedded credentials. The port is the one the sandbox connects to, which is the
published port, not the bound one, wherever NAT sits in between.

Getting this wrong isn't dangerous, only slow to diagnose: the sandbox's fetch
can't connect, but no credential goes anywhere it shouldn't.

### What a dispatch does

No driver knows about the proxy. `pkg/executor/gitproxycreds` wraps the
`executor.WorkspaceCredentialSource` a driver would use anyway:

1. the inner source leases the forge credential from the broker, as before;
2. that credential stays on the hub, and a session is minted against it;
3. the driver receives an `executor.WorkspaceAccess` (the session token plus
   `Minted.RepoURL`), and `Apply` rewrites the workspace's `Repo` for every git
   command that follows, both the provisioning fetch and the write-back push.

Returning the URL together with the credential makes the redirection hard to
skip. A driver that ignored `Repo` would send the sandbox to the forge with a
token the forge has never seen, which fails at once instead of falling back to
the unproxied path unnoticed.

Two behaviours to know about:

**It fails closed.** If `Mint` fails, the dispatch fails: the inner lease is
released and the error names the repository. Falling back to the direct
credential would give the sandbox the PAT at the moment the proxy is broken.

**A public repository isn't proxied.** An empty credential means an
unauthenticated fetch. There is nothing to keep from the sandbox, so a session
would only add a hop that can fail.

The credential the driver sees has no `ExpiresAt`. The hub keeps track of the
session's deadline, renewing it while the run lives and ending it when the run
is done with it (see
[a workspace session lives as long as its run](#a-workspace-session-lives-as-long-as-its-run)).
A deadline handed to a device would be out of date by the time a long run came
to push, since the device refuses to push after the deadline it holds. Without
the proxy, the sandbox holds the PAT and its access never ends, whatever the
lease says.

Both drivers that provision git workspaces are routed through the proxy: the
Kubernetes driver through `reconcile.Options.WrapWorkspaceSource`, and the
remote agent through the hub's per-executor credential factory. The `container`
and `localprocess` drivers bind the operator's own checkout and never clone, so
they have no workspace to intercept, although their workloads' own git goes
through the proxy on the lease path below. Only `cloop ui` sets this up, because
only `cloop ui` runs the proxy. With the section enabled, every other process
that registers the Kubernetes driver, `cloop serve` among them, refuses git
workspaces instead of giving a Pod the forge credential. On Kubernetes the
routed fetch authenticates with the session id, which the per-run workspace
Secret carries next to the token. See
[limits that remain](architecture/git-proxy.md#limits-that-remain).

The PAT itself is a `secretbroker` lease like any other. What changes is where
it is used, not where it comes from. See
[GitHub repositories and PATs](guides/secrets.md#github-repositories-and-pats).

### What a GitHub lease does

The workspace is cloop's own git. The workload's git (whatever the agent clones
and pushes) reaches the proxy by a second path, through the secret broker
instead of a driver. When a lease includes a `github_pat` or `github_app` grant,
the broker hands the token to a `secretbroker.GitGuard`, which the hub
implements on this proxy. It mints a
[scoped session](#scoped-sessions-an-allowlist-instead-of-one-repository) over
the grant's repository allowlist, under the hub's policy narrowed by the grant's
permissions and branches. The sandbox receives a session credential, a
credential helper and a gitconfig that rewrites `https://github.com/` to the
proxy. The session is closed when the lease is released.
[Git proxy architecture](architecture/git-proxy.md#what-the-sandbox-holds)
describes what the files contain, and which credential each kind of hub
delivers instead.

---

## Audit events

`Registry.OnEvent` receives every authorisation decision as an `Event`. Events
carry ids, ref names and reasons, but no credentials or object content, so they
are safe to write to a log that operators read. `Event.String()` renders one as a
single line.

| Kind | Emitted when | Notes |
| --- | --- | --- |
| `push_denied` | a push was refused by policy | The most important row. It shows the policy held, and it is the only record of a sandbox's attempt to reach a protected branch: nothing else in cloop records it. Alert on it. A push the [scan](#the-push-scan) couldn't finish (past a limit, or unreadable) is one too, with `Scan` set. |
| `push_secret_refused` | a push carried a credential the run was given | `Findings` name each object, its path and commit, and the grant and secret. `Refs` have the run's values taken out. Never the value. |
| `push_allowed` | every command in a push passed policy, and its pack carried none of the run's credentials | Emitted before the forge's answer is forwarded, so it records what was authorised, not what the remote finally accepted. Its `Detail` says how many objects the scan read. A `push_allowed` with no matching change on the forge means the forge refused the push (branch protection, a non-fast-forward), not the proxy. |
| `session_minted` | a session was created | `Detail` carries the allowlist and the expiry. |
| `session_closed` | a session was revoked or reaped | `Detail` carries the reason and the session's push/fetch/denied counters. |
| `fetch` | a read went through the proxy | |
| `rejected` | a request was refused before the policy ran | A credential that failed (unknown, wrong, expired or revoked), a repository outside the session's scope, malformed pkt-lines, a route the proxy doesn't serve, or an upstream stream that ended early. Unlike `push_denied`, none of these got as far as a decision about a ref. A request that presented no credential at all is not an event (see below). |

Every per-request event names the repository the request addressed, not the
session's: a scoped session (a guarded GitHub lease) has no single repository,
and a refused request is about the one the sandbox tried. An admitted path is
recorded normalised (`owner/name`, lowercase, no `.git`), and a refused one as
it arrived. `session_minted` and `session_closed` name what the session admits:
its repository, or its allowlist.

A request that presents no credential at all gets a 401 and is counted in
`cloop_gitproxy_anonymous_requests_total`, but no event is emitted. Nearly all
of these are git's own challenge: git sends each request without credentials and
asks the lease's credential helper only after the 401. Auditing them wrote a
`rejected` row before the real one for every clone, fetch and push through a
guarded lease, which was half the proxy's rows on a live hub. The rest are
whatever else reaches the port. None carries an identity or a decision about a
session, and auditing them let anything that can open a connection add rows to
the hash-chained trail. A credential that fails is still a `rejected` row.

`OnEvent` runs on the request goroutine, so a handler that blocks also blocks
the push. Hand events off to a queue if the sink can be slow. The hub's own sink
does a single insert for that reason.

### Where they land

The hub writes every event to the same hash-chained `audit_events` table as the
credential broker, with `entity_type` `gitproxy`, the session id as the entity,
and the event type prefixed: `gitproxy.push_denied`,
`gitproxy.push_secret_refused`, `gitproxy.push_allowed`,
`gitproxy.session_minted`, `gitproxy.session_closed`, `gitproxy.fetch`,
`gitproxy.rejected`. The payload carries the session, the repository, the
project and task ids, the ref names and the reason (the same fields
`Event.String()` renders), and, for a push the scan refused, the run and the
findings. `gitproxy.Event` has no field that could hold credential material or
object content, so the table is safe to export.

```console
$ cloop audit-log list --entity gitproxy --since 7d
$ cloop audit-log list --type gitproxy.push_denied --since 30d --json
```

If an audit write fails, the push doesn't fail, but the decision still goes
somewhere: to stderr, prefixed `git-proxy:`. So does every event on a hub whose
database didn't open.

Don't tune `push_denied` away as a false positive. A well-behaved SDK-driven
task never produces one, so each one is either a workload doing something it
wasn't asked to do, or a policy narrower than the task it was minted for. Both
need a person to look at them.

---

## Threat model notes

As in the [threat model](security/threat-model.md), assume the workload is
hostile. The question is what each leaked credential allows.

| Leaked | Worth |
| --- | --- |
| **Workspace session token** | What the policy allows, until its run is done with it: push to `refs/heads/cloop/**`, create and update only, on one repository, through one proxy, plus reading that repository, because the hub's policy sets `AllowFetch` so the clone can go through the proxy too. No deletes. No other repository the same proxy serves, because the session is pinned. Nothing against `github.com` directly, where the token means nothing. |
| **Guarded-lease session token** | The grant's repository allowlist instead of one repository, through one proxy, until the lease is released: reads, plus pushes inside both the hub's allowlist and the grant's branches if the grant carries `contents:write`. Never a delete. Still nothing against `github.com` directly. |
| **PAT delivered into the sandbox** (what a hub without the proxy does) | Every repository the token is scoped to, every ref in them, in every direction, from anywhere on the Internet, until someone notices and revokes it. |

More specifically:

- **Detection.** A session token leaves a `push_denied` row when a push is
  attempted. A PAT leaves a force-push notification after the push succeeds.
- **Revocation.** `Registry.Close` ends a session at the next request, with no
  round trip to the forge and no coordination. Revoking a leaked PAT means an
  API call to GitHub and, usually, issuing a new token for everything else that
  used it.
- **Exposure of the proxy host.** The proxy is a process holding forge
  credentials for every live session. It must not run inside a sandbox, must be
  reachable only from the sandbox network, and its logs are as sensitive as its
  memory, which is why events carry no credentials and errors are scrubbed. In
  the shipped setup that process is the hub, which already holds the sealing key
  and every stored credential, so the proxy doesn't gather secrets in a new
  place. It does add a second listener on the hub, reachable by everything the
  sandbox network can reach, so bind `listen_addr` as narrowly as that network
  allows.
- **Compromised proxy.** Nothing here protects against that: a compromised proxy
  is a compromised credential store. What improves is that there is one such
  store to protect, instead of one per running sandbox.
- **Push content.** The proxy only checks that a push carries none of the run's
  own credentials, in the encodings the [push scan](#the-push-scan) matches.
  Otherwise a sandbox may write anything to a branch it is allowed to write to.
  Checking content is the job of `pkg/writeback`'s inspection (see
  [Result write-back](security/model.md#the-guarantee--test-table)): the proxy
  decides where a push goes, and the inspection decides what it may contain.
- **Fast-forward and branch protection.** Still the forge's job, as above. A hub
  that relies on this proxy alone hasn't protected `main` from history rewriting
  within the namespaces it allows.

---

## See also

- [Git proxy architecture](architecture/git-proxy.md): how the proxy is wired
  into the hub, the workspace and lease paths into it, each executor's part, what
  a sandbox holds, and the limits that remain
- [Security model](security/model.md): the trust boundaries, the workspace
  credential's path, and the guarantee → test table
- [Threat model](security/threat-model.md): STRIDE per boundary, with the
  residual-risk column
- [Executor architecture](architecture/executors.md): where a sandbox comes from
  and how a work product gets back
- [Secret and egress grants](guides/secrets.md): how the PAT the proxy holds is
  granted in the first place
- [Operator runbook](operations/runbook.md): TLS material, rotation, and audit
  export
- [`pkg/gitproxy/proxy.go`](../pkg/gitproxy/proxy.go): the package comment this
  document expands on
