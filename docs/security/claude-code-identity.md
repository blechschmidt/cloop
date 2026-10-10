# Per-user Claude Code logins

How a hub with single sign-on gives every signed-in user their own Claude
account — and the one environment variable that quietly takes it away again.

The `claudecode` provider holds no credential of its own. It runs the `claude`
binary once per call and inherits whatever that CLI is signed in as (see
[providers](../getting-started/providers.md)). On a laptop that is exactly
right. On a hub with more than one person on it, it means the deployment has
**one** Claude account, because `claude auth login` writes to a single
well-known location derived from the process's `HOME`.

With OIDC enabled, cloop gives each signed-in identity a private Claude CLI
configuration directory and scopes every login, logout, status read, usage
figure and dispatched run to the caller's own. There is no new configuration
key: the switch is OIDC itself.

- [What it closes](#what-it-closes)
- [Turning it on](#turning-it-on)
- [Where the credential lives](#where-the-credential-lives)
- [The ambient token outranks the directory](#the-ambient-token-outranks-the-directory)
- [What is scoped, and to what](#what-is-scoped-and-to-what)
- [Isolating executors do not get a directory](#isolating-executors-do-not-get-a-directory)
- [Callers with no identity](#callers-with-no-identity)
- [Deprovisioning a user](#deprovisioning-a-user)
- [What this does not do](#what-this-does-not-do)

---

## What it closes

A pooled credential is not one problem, it is four, and they compound:

| | What happens on a shared login |
| --- | --- |
| **Attribution** | Every user's tasks run as whoever logged in last. The account's activity is the hub's activity; no part of it can be traced back to the person who asked for it. |
| **Quota** | One tenant's plan session can exhaust the five-hour and weekly windows for everybody. The [subscription caps](../getting-started/web-ui.md#a-projects-overview) panel then reports one person's utilisation to all of them, which is both a disclosure and a lie to everyone else. |
| **Eviction** | The next person to sign in silently replaces the credential. The previous owner's runs continue — on the new person's subscription. |
| **Logout** | `claude auth logout` is a hub-wide event. One user tidying up signs out every other tenant mid-run. |

There is a fifth that is easy to miss: the CLI keeps **all** of its per-account
state in the same directory — credential, session transcripts and project
history. A shared directory pools the conversations, not only the token.

---

## Turning it on

Nothing to turn on. `pkg/ui/claude_identity.go` keys off
`ui.oidc.enabled`, so the behaviour follows the one decision an operator has
already made:

| Deployment | Claude account used |
| --- | --- |
| No OIDC (`ui.oidc.enabled` unset or `false`) | The host's own `~/.claude`, exactly as before. One machine, one operator, one credential. |
| OIDC on | The requesting identity's private directory. |
| OIDC on, identity unresolvable | Nothing. The auth and usage endpoints return `403`; see [callers with no identity](#callers-with-no-identity). |

The identity is the same one the rest of the dashboard filters by — the browser
session user, or, for a token minted on someone's behalf, that someone. Its
**owner key** is the lowercased email, or `sub:<subject>` when the IdP supplies
no email (`pkg/oidcauth/oidcauth.go`, `Identity.OwnerKey`).

**RBAC still applies on top.** Reading login status and usage needs
`project.read`; starting or finishing a login, cancelling one, and logging out
need `config.write` — so on a hub that has written a role policy, a `viewer` or
`operator` can see that they are signed out but cannot sign themselves in. Grant
`maintainer` on the hub to the people who are expected to bring their own Claude
account. See [roles and permissions](model.md#identity-roles-and-permissions).

**Strict no-host-execution still applies underneath it.** The four
`/api/claudecode/auth/*` endpoints run the `claude` binary on the hub, so they
remain gated by `denyHostSideEffect` and return `409` when
`executors.allow_host_process: false`. A strict hub does not offer dashboard
login to anybody, per-user or otherwise — its sandboxes get credentials through
the broker instead.

---

## Where the credential lives

```
$XDG_CONFIG_HOME/cloop/claude-identities/<slug>/      0700
   └── .credentials.json          the OAuth access + rotating refresh token
   └── …                          the CLI's session transcripts and history
```

`$XDG_CONFIG_HOME` falls back to `~/.config`, matching the convention
`pkg/workspace` and `pkg/globalbudget` already use. Both the
`claude-identities` root and each identity directory are created `0700` and
re-`chmod`ed to `0700` on every resolution, so a tree created by an older build
or loosened by hand is tightened the next time anyone touches it
(`pkg/claudecodeauth/identity.go`).

`<slug>` is `sha256(owner_key)` hex-encoded and truncated to 32 characters, over
the owner key lowercased and trimmed. Hashing is not obfuscation — an IdP
subject is whatever the issuer says it is, and an email can contain `/` or
`..`, differ from another only by case on a case-insensitive filesystem, or
exceed `NAME_MAX`. The mapping is deliberately unsalted so an operator can
recompute it with nothing but a shell:

```console
$ printf '%s' 'dana@example.com' | sha256sum | cut -c1-32
07e2f1394b0ea80e2adca010ea8318df
```

**It is under the hub's config directory and not under any project tree, on
purpose.** A task runs an agent *inside* a project working directory. A
credential stored there would be readable by exactly the code it is meant to be
isolated from, and every peer's agent would find it by walking the tree.

---

## The ambient token outranks the directory

This is the part that has to be right, because getting it wrong produces
isolation that looks correct and is not.

`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` hand
the CLI a credential **without it ever consulting its configuration
directory**. Measured against the real CLI: an empty config directory plus an
ambient `CLAUDE_CODE_OAUTH_TOKEN` reports

```json
{ "loggedIn": true, "authMethod": "oauth_token" }
```

and prompts execute on the host's account. A user who has never logged in would
appear signed in, spend someone else's subscription, and have no way to tell.

cloop is not a bystander here: it populates `CLAUDE_CODE_OAUTH_TOKEN` itself
from `~/.openclaw/workspace/.env` and `~/.env` (`loadEnvFiles` in
`pkg/provider/claudecode`). Two changes close the gap:

- **`claudecodeauth.ScopeEnv(env, configDir)`** rewrites an environment so the
  CLI resolves its credential from `configDir` and nowhere else: the three
  variables are appended as *empty* assignments — exec keeps the last
  occurrence of a key — and `CLAUDE_CONFIG_DIR` is set. It is applied to every
  `claude` subprocess: the login and status calls the hub makes directly, and
  the provider's own `runCLI`.
- **`claudecodeauth.ScopeHarnessEnv(env, configDir)`** does the same for a
  dispatched `cloop run`, but clears only `CLAUDE_CODE_OAUTH_TOKEN`. That
  environment belongs to a whole harness rather than to one program, and the
  harness may be running a different provider entirely — see [the scoping
  split](#why-two-scoping-functions) below.
- **`loadEnvFile` skips `CLAUDE_CODE_OAUTH_TOKEN`** when `CLAUDE_CONFIG_DIR` is
  set, rather than importing a value that something downstream then has to
  clear. A configuration directory names the identity to authenticate as;
  reading a credential out of the host's dotfiles would override that choice
  with the host's own account.

With `configDir` empty — every deployment without OIDC — both functions return
the environment untouched and ambient tokens keep working as they always have.

### Why two scoping functions

`ANTHROPIC_API_KEY` is ambient for the Claude CLI, but it is also how
`pkg/provider/anthropic` finds its key. Clearing it everywhere would isolate a
provider the project may not even be using and break one it is: an
`anthropic`-provider run on an OIDC hub would fail with `ANTHROPIC_API_KEY not
set`.

So the two environments are treated differently, and the layering still closes
the hole:

| Environment | Function | Cleared |
| --- | --- | --- |
| A `claude` subprocess | `ScopeEnv` | `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` |
| A dispatched `cloop run` | `ScopeHarnessEnv` | `CLAUDE_CODE_OAUTH_TOKEN` |

The harness keeps other providers' credentials, and when its claudecode
provider finally spawns the CLI it re-scopes with the stricter `ScopeEnv` — so
the `claude` binary never sees an ambient credential either way.

> **Do not export a hub-wide `CLAUDE_CODE_OAUTH_TOKEN` (or
> `ANTHROPIC_AUTH_TOKEN`) into the `cloop ui` service and expect per-user mode
> to still isolate.** Inside cloop's own processes it is cleared, so the token
> is at best dead weight. Anything it reaches that cloop did not start — a
> shell on the box, a hook, a wrapper script that re-exports it *after*
> `ScopeEnv` has run — sees the host account again, and the last assignment of
> a key is the one exec keeps. If the hub needs a fallback credential for
> unattended work, give it to a project through a
> [secret grant](../guides/secrets.md#environment-secrets), where it is leased,
> scoped and revocable, rather than to the service environment where it is
> global and permanent.

**No migration needed for other providers.** A deployment that exports
`ANTHROPIC_API_KEY` or `OPENAI_API_KEY` into the `cloop ui` service environment
keeps working: those reach the dispatched harness untouched, and only the
`claude` subprocess sees them cleared. Config-file keys
(`anthropic.api_key`, `openai.api_key`) were never involved.

---

## What is scoped, and to what

Everything downstream of the credential had to move with it, because a
per-user token behind a process-global cache is still a shared account by the
time a user sees it.

| Scoped by configuration directory | Where |
| --- | --- |
| Credential file path, and the OAuth refresh that rotates it | `pkg/ratelimit`, `credentialsPathIn` / `loadCredentialsIn` |
| The cross-process refresh lock | `<configDir>/.credentials.json.lock` — two users refreshing contend only with peers holding the same credential |
| The usage snapshot the caps panel renders | `FetchOrCachedUsageIn`, `GetCachedUsageIn`, `ClearUsageCacheIn` |
| The classified auth-failure cache (1 min) behind the re-authenticate banner | `AuthFailureIn`, `ReauthRequiredIn` |
| The transient fetch-error backoff (30 s) | same file |
| In-flight `claude auth login` sessions | keyed by owner key in `claudecodeauth.Manager` |
| Dispatched runs | `startWorkloadAs` — `/api/run`, project run, and new-project autorun |
| Provider-invoking subcommands | `runCloopSubcommandFor` — the Tasks tab's **brainstorm** (`cloop suggest`) and the assistant chat (`cloop do`), both of which spend tokens on the caller's behalf |
| A sandboxed run's personal Claude credential | `harnessClearance` — counted for, and leased to, only runs its owner starts (see [isolating executors](#isolating-executors-do-not-get-a-directory)) |

Two consequences worth stating outright. One user's expired token no longer
raises a "re-authenticate" banner on everyone else's dashboard, and one user's
successful login no longer clears a warning that is still true for the rest.
And a pasted OAuth code can only ever complete the pasting user's own login
flow — sessions are keyed by identity, so two people logging in at the same
time do not evict each other.

`cacheTokenInEnv` is the sharp edge in that list. Refreshing a token used to
publish it into the process environment, where later subprocesses pick it up.
On a hub that refreshes on behalf of whoever is asking, that would hand user A's
token to every run started afterwards — including user B's. It is now a no-op
unless the directory is the one *this* process is itself pinned to.

For the same reason, the ambient-token fallback in `resolveCredentialToken`
applies only to the host default directory. Under an explicit per-identity
directory, a user with no credential of their own is **logged out**, and the
error says so, rather than transparently spending the host's subscription.

**Session bounds.** At most 32 login flows may be in flight hub-wide; each one
is a live `claude auth login` child parked on stdin, so an unbounded map would
be a process-exhaustion lever for any authenticated user with a script.
Finished sessions are reaped 10 minutes after they end — long enough for the
dashboard to render the outcome — and every parked child is killed when the hub
shuts down.

**What the user sees.** `GET /api/claudecode/auth/status` returns a `per_user`
boolean, and the Budget tab renders it as a note saying the login is theirs
alone, that other users sign in separately, and that signing out here does not
sign anyone else out. A hub-wide settings page that is quietly per-user is
worse than either.

---

## Isolating executors do not get a directory

A per-user configuration directory is a path on the hub's filesystem. Inside a
container, a Pod or an enrolled edge device it names nothing. So
`claudeWorkloadEnv` returns nothing at all when
`executor.IsolatesFromHost(ex)` is true:

| Backend | Isolation | Gets `CLAUDE_CONFIG_DIR` |
| --- | --- | --- |
| `localprocess` | `IsolationNone` | yes — it runs on the hub, sharing this filesystem |
| `container` | `IsolationContainer` (`IsolationVM` under Kata) | no |
| `kubernetes` | `IsolationRemote` | no |
| `remote` | `IsolationRemote` | no |

This is not a gap that per-user logins left open; it is the boundary working.
The hub deliberately does not forward its own environment into an isolating
executor, and a sandbox that could read the hub's `~/.config` would not be a
sandbox. Those workloads get credentials the way every other credential reaches
them — [through the secret broker](../guides/secrets.md#environment-secrets),
as a leased `env` grant scoped to a project or an executor, delivered for the
life of one workload:

```console
$ printf '{"ANTHROPIC_API_KEY":"sk-ant-…"}' | cloop secret mint claude-api --kind env
$ cloop secret grant claude-api --to project:/srv/app --env-keys ANTHROPIC_API_KEY --ttl 8h
```

The payload is a JSON object. Until Task 20379 this page showed
`ANTHROPIC_API_KEY=sk-ant-…` piped in as a line, which the broker stores as one
bare value under the name `CLAUDE_API` — the grant above then delivers nothing,
and the run reaches `claude` logged out. The dashboard's *Claude credential*
dialog (below) builds the object itself.

### Checked before dispatch

A sandbox with no credential used to start anyway — a device sometimes
installing `claude` first — and fail its first task `auth_refused`, with *Not
logged in* in a transcript that said nothing about grants. Expired grants failed
the same way. Since Task 20379 every path that dispatches a harness to an
isolating executor — `/api/run`, a project's Run, the new-project autorun, the
automatic resume after a usage cap, the Tasks tab's brainstorm and plan, the
assistant chat and a reproduction — settles one preflight
(`pkg/ui/harness_credential.go`) against the executor it resolved, before
anything is leased or started. It computes the environment the run's lease would
carry — the same grants, matched as a lease matches them (a feature through its
parent project), narrowed by each grant's `env_keys` and by the project's
`.cloop/sandbox.yaml` `env:` list — and refuses with a `409` when that holds no
credential the provider reads (`harness_credential_missing`), or when the only
grant that does ends within ten minutes (`harness_credential_expiring`) — or
the lease itself does, since a lease ends with the first of its grants to expire,
whatever kind. The provider is judged as the sandbox will choose it: a container
from the project's own `config.yaml` and state, never the hub's environment; a
device or a Pod from the provider its seeded state carries — the hub's resolution
for the project — or a `config.yaml` its repository commits, refusing on neither
where the two could differ. The refusal names the executor and the remedy.
`tests/arch` pins that every dispatch path builds the preflight and that the
dispatch primitives settle it before they lease. Host executors, providers other
than `claudecode` and `anthropic`, and executors the hub lists in
`executors.harness_credential_exempt` (a device signed in as its agent user, an
image that brings a key) are not refused.

The project's Overview shows the result as a *Claude credential* card whenever
the executor isolates, and its dialog grants an existing `env` secret or a
pasted token in one step — see [the Claude credential of a sandboxed
run](../guides/secrets.md#the-claude-credential-of-a-sandboxed-run). The API is
`GET`/`POST /api/projects/{idx}/harness-credential`.

**Say plainly what that means:** on an isolating executor the split is
per-project or per-executor for a *shared* credential: every task placed there
uses whatever the grant carries, whoever pressed Run. A *personal* one — an
`env` secret a signed-in user owns, which is what the dialog stores a pasted
token as — is per-user, as the configuration directory is on the hub: with OIDC
on, the preflight counts it only for runs its owner starts, and every other
lease the hub issues — runs on any executor, the host included, and workloads
that run no harness at all — is told to withhold it
(`secretbroker.Requester.Withhold`), recording a `secret.lease` denial that names
the grant and why. Without that, a token granted to a shared project would bill
its owner's subscription for every member's runs, and a project holding two
people's tokens would authenticate with whichever the lease rendered last. On the
host it would also undo this page's work: a leased token is appended after
`ScopeHarnessEnv`'s cleared assignment, and the last occurrence of a key is the
one exec keeps. An automatic resume acts for whoever started the run it resumes,
recorded in the hub's own database at dispatch — never in the project's tree,
which the sandbox can write. A static-token or service-token run acts for no
one, so only a shared credential satisfies it. If a deployment needs per-user
billing end to end, each user grants their own; if it needs a team account, a
maintainer grants a shared one.

Note the direction of `IsolatesFromHost`: a driver that declares no isolation
level is treated as **not** isolated, so it does receive the directory. That is
the right default here — a workload that runs on the hub can read the path, and
one that does not is refused separately by
[strict no-host-execution](model.md#the-no-host-execution-guarantee) rather than
being quietly credited with isolation it never claimed.

---

## Callers with no identity

With OIDC on, `claudeScopeFor` **fails closed**. "I could not tell who you are"
must never resolve to "then use the shared account everyone can see", so the
auth and usage endpoints answer `403` rather than falling back:

- the static bearer token (`--token` / `CLOOP_UI_TOKEN`), which carries no
  owner binding,
- a scoped API token from `cloop hub token create`, which is minted with roles
  but not on a user's behalf.

Delegated links *do* resolve: a display-glasses token is minted bound to its
owner, so it reads that owner's Claude status and usage, matching the rest of
its behaviour.

The **run dispatch** path is the one asymmetry. `claudeWorkloadEnv` returns
nothing when the scope cannot be resolved, so a run started by one of those
callers executes on the host credential rather than failing. The endpoints fail
closed; the dispatch falls back. That is deliberate — refusing would break
non-interactive automation on every hub that has one — but it means **an
unattended caller's runs are not attributed to any user**. If that matters,
either give automation its own project on an isolating executor with its own
grant, or do not leave a host credential for it to fall back to. Runs started
outside HTTP entirely — `cloop run` on the hub, a scheduled job — are in the
same position for the same reason.

---

## Deprovisioning a user

Removing someone from the IdP group stops them signing in. It does not touch
the refresh token sitting in their directory, and `claude auth logout` revokes
the session while leaving the directory populated. A hub that keeps a former
employee's rotating refresh token on disk has not really removed them.

Offboarding does it (Task 20400): `cloop hub user offboard` and **Secrets →
Offboard a user** end the person's Claude Code login for every spelling of
them — their email, and `sub:<subject>` from any time the IdP withheld it —
on every hub member:

1. a `claude auth login` they had in flight is cancelled, on the member holding
   it, and that member gives up its claim on it;
2. each home with a credential is logged out with `claude auth logout`, scoped
   to that directory alone, which revokes the session at Anthropic and not only
   on disk. Best-effort: a failure is reported and the directory goes anyway.
   A hub with `executors.allow_host_process: false` skips it, because it runs
   no program on a request's behalf, and says so; the CLI, an operator's shell,
   runs it for the tree beside it whatever the policy. A home that is a
   symbolic link is never logged out through — that would sign out whatever the
   link points at — and is removed without being followed;
3. the directory is removed with `claudecodeauth.ForgetHome`, credential and
   transcripts together. The person's tasks were told to stop just before, so
   a run of theirs is not still writing there.

A home lives under the config directory of the process that created it, so a
cluster whose members run under different users or container filesystems keeps
one per member. The member serving a dashboard offboarding asks the others over
the peer channel; the CLI asks them over the bus. A member that cannot be asked
is reported, never assumed empty — see
[offboarding in the security model](model.md#offboarding-what-a-departed-identity-keeps).
Under a legal hold (`--keep-credentials`) the login in flight is still cancelled
and the homes are kept as they are.

By hand, on a host the run could not reach, recompute the slug and remove the
directory:

```console
$ slug=$(printf '%s' 'dana@example.com' | sha256sum | cut -c1-32)
$ rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/cloop/claude-identities/$slug"
```

Removing a directory is safe while the hub is running — a request from that
identity would recreate an empty one, and the user would simply be logged out —
but after an offboarding there is none: the identity is denied.

---

## What this does not do

- **It does not revoke anything upstream.** Deleting a directory destroys the
  hub's copy of a credential. The Claude account itself is unaffected; only the
  user (or Anthropic) can revoke the OAuth grant.
- **It does not separate quota.** Each user spends their own subscription,
  which is the point — but cloop enforces no ceiling across users. Use
  [quotas](model.md#quotas-how-much-not-whether) for hub-side limits.
- **It does not reach isolating executors** with a directory, as above; there a
  user's own Claude login is a personal `env` grant, spent only on their runs.
- **It does not survive a hostile host.** Every identity's directory lives under
  one uid on one filesystem. `0700` stops other *users* of that machine; it
  stops nothing that already runs as the hub, which includes any agent executed
  on `localprocess`. That is one more reason
  [`executors.allow_host_process: false`](model.md#the-no-host-execution-guarantee)
  is the recommended posture, and per-user logins do not change the
  recommendation.

---

See also: [security model](model.md), [threat model](threat-model.md),
[providers](../getting-started/providers.md), and
[granting secrets](../guides/secrets.md).
