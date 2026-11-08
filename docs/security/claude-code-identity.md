# Per-user Claude Code logins

How a hub with single sign-on gives every signed-in user their own Claude
account, and the one environment variable that can take it away again without
any error.

The `claudecode` provider holds no credential of its own. It runs the `claude`
binary once per call and uses whatever account that CLI is signed in to (see
[providers](../getting-started/providers.md)). On a laptop that is what you
want. On a hub used by more than one person, it means the deployment has a
single Claude account, because `claude auth login` writes to one well-known
location derived from the process's `HOME`.

With OIDC enabled, cloop gives each signed-in identity a private Claude CLI
configuration directory, and scopes every login, logout, status read, usage
figure and dispatched run to the caller's own directory. There is no new
configuration key: turning on OIDC turns this on. The `copilot` provider's
equivalent is [per-person Copilot credentials](copilot-identity.md).

- [What it closes](#what-it-closes)
- [Turning it on](#turning-it-on)
- [Where the credential lives](#where-the-credential-lives)
- [The ambient token outranks the directory](#the-ambient-token-outranks-the-directory)
- [What is scoped, and to what](#what-is-scoped-and-to-what)
- [Isolating executors do not get a directory](#isolating-executors-do-not-get-a-directory)
- [Resumed and failed-over runs](#resumed-and-failed-over-runs)
- [Callers with no identity](#callers-with-no-identity)
- [Deprovisioning a user](#deprovisioning-a-user)
- [What this does not do](#what-this-does-not-do)

---

## What it closes

A shared credential causes four problems:

| | What happens on a shared login |
| --- | --- |
| **Attribution** | Every user's tasks run as whoever logged in last. The account's activity is the hub's activity, and none of it can be traced back to the person who asked for it. |
| **Quota** | One tenant's plan session can use up the five-hour and weekly windows for everybody. The [subscription caps](../getting-started/web-ui.md#a-projects-overview) panel then shows one person's usage to all of them, which discloses it and is wrong for everyone else. |
| **Eviction** | The next person to sign in replaces the credential without any warning. The previous owner's runs continue, on the new person's subscription. |
| **Logout** | `claude auth logout` affects the whole hub. One user signing out signs out every other tenant, even mid-run. |

There is a fifth: the CLI keeps all of its per-account state in the same
directory, including the credential, session transcripts and project history.
A shared directory shares the conversations as well as the token.

---

## Turning it on

There is nothing to turn on. `pkg/ui/claude_identity.go` follows
`ui.oidc.enabled`:

| Deployment | Claude account used |
| --- | --- |
| No OIDC (`ui.oidc.enabled` unset or `false`) | The host's own `~/.claude`, as before: one machine, one operator, one credential. |
| OIDC on | The requesting identity's private directory. |
| OIDC on, identity unresolvable | Nothing. The auth and usage endpoints return `403`; see [callers with no identity](#callers-with-no-identity). |

The identity is the same one the rest of the dashboard filters by: the browser
session's user or, for a token minted on someone's behalf, that person. Its
**owner key** is the lowercased email, or `sub:<subject>` when the IdP supplies
no email (`pkg/oidcauth/oidcauth.go`, `Identity.OwnerKey`).

**RBAC still applies.** Reading login status and usage needs `project.read`.
Starting, finishing or cancelling a login, and logging out, need
`config.write`. So on a hub with a role policy, a `viewer` or `operator` can
see that they are signed out but cannot sign themselves in. Grant `maintainer`
on the hub to the people who are expected to bring their own Claude account.
See [roles and permissions](model.md#identity-roles-and-permissions).

**Strict no-host-execution still applies.** The four `/api/claudecode/auth/*`
endpoints run the `claude` binary on the hub, so they are still gated by
`denyHostSideEffect` and return `409` when
`executors.allow_host_process: false`. A strict hub offers dashboard login to
nobody, per-user or otherwise. Its sandboxes get credentials through the broker
instead.

---

## Where the credential lives

```
$XDG_CONFIG_HOME/cloop/claude-identities/<slug>/      0700
   └── .credentials.json          the OAuth access + rotating refresh token
   └── …                          the CLI's session transcripts and history
```

`$XDG_CONFIG_HOME` falls back to `~/.config`, the same convention
`pkg/workspace` and `pkg/globalbudget` use. Both the `claude-identities` root
and each identity directory are created `0700` and set back to `0700` with
`chmod` on every resolution, so a tree created by an older build or loosened by
hand is tightened the next time anyone uses it
(`pkg/claudecodeauth/identity.go`).

`<slug>` is `sha256(owner_key)` hex-encoded and truncated to 32 characters,
computed over the owner key lowercased and trimmed. The hash makes a safe
directory name; it does not hide anything. An IdP subject is whatever the
issuer says it is, and an email can contain `/` or `..`, differ from another
only by case on a case-insensitive filesystem, or exceed `NAME_MAX`. The
mapping is unsalted so that an operator can recompute it with a shell:

```console
$ printf '%s' 'dana@example.com' | sha256sum | cut -c1-32
07e2f1394b0ea80e2adca010ea8318df
```

The directory is under the hub's config directory, not under any project tree.
A task runs an agent *inside* a project working directory, so a credential
stored there would be readable by the very code it is meant to be isolated
from, and every peer's agent would find it by walking the tree.

---

## The ambient token outranks the directory

A mistake in this part gives isolation that looks correct but is not.

`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` give
the CLI a credential without it ever reading its configuration directory.
Tested against the real CLI, an empty config directory plus an ambient
`CLAUDE_CODE_OAUTH_TOKEN` reports
```json
{ "loggedIn": true, "authMethod": "oauth_token" }
```

and prompts run on the host's account. A user who has never logged in would
appear signed in, spend someone else's subscription, and have no way to tell.

cloop itself sets `CLAUDE_CODE_OAUTH_TOKEN` from `~/.openclaw/workspace/.env`
and `~/.env` (`loadEnvFiles` in `pkg/provider/claudecode`). Three changes
close the gap:

- **`claudecodeauth.ScopeEnv(env, configDir)`** rewrites an environment so the
  CLI takes its credential from `configDir` and nowhere else. The three
  variables are appended as *empty* assignments (exec keeps the last occurrence
  of a key), and `CLAUDE_CONFIG_DIR` is set. It is applied to every `claude`
  subprocess: the login and status calls the hub makes directly, and the
  provider's own `runCLI`.
- **`claudecodeauth.ScopeHarnessEnv(env, configDir)`** does the same for a
  dispatched `cloop run`, but clears only `CLAUDE_CODE_OAUTH_TOKEN`. That
  environment belongs to a whole harness, not to one program, and the harness
  may be running a different provider entirely; see
  [the scoping split](#why-two-scoping-functions) below.
- **`loadEnvFile` skips `CLAUDE_CODE_OAUTH_TOKEN`** when `CLAUDE_CONFIG_DIR` is
  set, instead of importing a value that something downstream then has to
  clear. A configuration directory names the identity to authenticate as, and
  reading a credential from the host's dotfiles would replace that choice with
  the host's own account.

With `configDir` empty, as in every deployment without OIDC, both functions
return the environment unchanged and ambient tokens work as before.

### Why two scoping functions

`ANTHROPIC_API_KEY` is an ambient credential for the Claude CLI, but it is also
how `pkg/provider/anthropic` finds its key. Clearing it everywhere would
isolate a provider the project may not be using and break one it is using: an
`anthropic`-provider run on an OIDC hub would fail with
`ANTHROPIC_API_KEY not set`.

So the two environments are treated differently, and the layering still closes
the gap:

| Environment | Function | Cleared |
| --- | --- | --- |
| A `claude` subprocess | `ScopeEnv` | `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` |
| A dispatched `cloop run` | `ScopeHarnessEnv` | `CLAUDE_CODE_OAUTH_TOKEN` |

The harness keeps other providers' credentials, and when its claudecode
provider starts the CLI it scopes the environment again with the stricter
`ScopeEnv`, so the `claude` binary never sees an ambient credential either way.

> **Do not export a hub-wide `CLAUDE_CODE_OAUTH_TOKEN` (or
> `ANTHROPIC_AUTH_TOKEN`) into the `cloop ui` service and expect per-user mode
> to still isolate users.** Inside cloop's own processes it is cleared, so at
> best the token does nothing. Anything it reaches that cloop did not start (a
> shell on the box, a hook, a wrapper script that exports it again *after*
> `ScopeEnv` has run) sees the host account again, because exec keeps the last
> assignment of a key. If the hub needs a fallback credential for unattended
> work, give it to a project through a
> [secret grant](../guides/secrets.md#environment-secrets), where it is leased,
> scoped and revocable, not to the service environment, where it is global and
> permanent.

**Other providers need no migration.** A deployment that exports
`ANTHROPIC_API_KEY` or `OPENAI_API_KEY` into the `cloop ui` service environment
keeps working: those variables reach the dispatched harness unchanged, and only
the `claude` subprocess sees them cleared. Config-file keys
(`anthropic.api_key`, `openai.api_key`) are not affected.

---

## What is scoped, and to what

Everything that depends on the credential is scoped with it, because a
per-user token behind a process-wide cache would still behave like a shared
account.

| Scoped by configuration directory | Where |
| --- | --- |
| Credential file path, and the OAuth refresh that rotates it | `pkg/ratelimit`, `credentialsPathIn` / `loadCredentialsIn` |
| The cross-process refresh lock | `<configDir>/.credentials.json.lock`: two users refreshing at once do not wait for each other, only for peers holding the same credential |
| The usage snapshot the caps panel renders | `FetchOrCachedUsageIn`, `GetCachedUsageIn`, `ClearUsageCacheIn` |
| The classified auth-failure cache (1 min) behind the re-authenticate banner | `AuthFailureIn`, `ReauthRequiredIn` |
| The transient fetch-error backoff (30 s) | same file |
| In-flight `claude auth login` sessions | keyed by owner key in `claudecodeauth.Manager` |
| Dispatched runs | `startWorkloadAs`: `/api/run`, project run and new-project autorun; and, acting for the run's recorded starter, the automatic resume after a usage cap, the cluster member a resume is handed to, and a failover's replacement (see [resumed and failed-over runs](#resumed-and-failed-over-runs)) |
| Provider-invoking subcommands | `runCloopSubcommandFor`: the Tasks tab's **brainstorm** (`cloop suggest`), the assistant chat (`cloop do`), the **Split** preview (`cloop task decompose --dry-run --json`), dictation's **Revise** (`cloop task revise`), the **blocker analysis** (`cloop task ai-blocker --json`) and the **plan assistant** (`cloop plan chat`), all of which spend tokens on the caller's behalf |
| Inline replays | `inlineClaudeEnv`: the provider-call and task replays call the provider in the hub's own process, so the caller's directory and cleared ambient tokens go into that call's environment (`provider.Options.Env`). claudecode's retry after a 401 does not swap the hub's own refreshed token into such a call |
| A sandboxed run's personal Claude credential | `harnessClearance`: counted for, and leased to, only runs its owner starts (see [isolating executors](#isolating-executors-do-not-get-a-directory)) |

As a result, one user's expired token no longer raises a "re-authenticate"
banner on everyone else's dashboard, and one user's successful login no longer
clears a warning that is still true for the others. A pasted OAuth code can
only complete the pasting user's own login flow. Sessions are keyed by
identity, so two people logging in at the same time do not evict each other.

`cacheTokenInEnv` needs care. Refreshing a token used to publish it into the
process environment, where later subprocesses pick it up. On a hub that
refreshes on behalf of whoever is asking, that would hand user A's token to
every run started afterwards, including user B's. It now does nothing unless
the directory is the one *this* process is itself pinned to.

For the same reason, the ambient-token fallback in `resolveCredentialToken`
applies only to the host's default directory. Under an explicit per-identity
directory, a user with no credential of their own is logged out, and the error
says so. The host's subscription is not used in their place.

**Session limits.** At most 32 login flows may be in progress hub-wide. Each
one is a live `claude auth login` child process waiting on stdin, so without a
limit any authenticated user with a script could exhaust the hub's processes.
Finished sessions are cleaned up 10 minutes after they end, long enough for the
dashboard to show the outcome, and every waiting child is killed when the hub
shuts down.

**What the user sees.** `GET /api/claudecode/auth/status` returns a `per_user`
boolean, and the Budget tab shows it as a note saying that the login is theirs
alone, that other users sign in separately, and that signing out here does not
sign anyone else out.

---

## Isolating executors do not get a directory

A per-user configuration directory is a path on the hub's filesystem, and it
names nothing inside a container, a Pod or an enrolled edge device. So
`claudeWorkloadEnv` returns nothing at all when
`executor.IsolatesFromHost(ex)` is true:

| Backend | Isolation | Gets `CLAUDE_CONFIG_DIR` |
| --- | --- | --- |
| `localprocess` | `IsolationNone` | yes: it runs on the hub and shares this filesystem |
| `container` | `IsolationContainer` (`IsolationVM` under Kata) | no |
| `kubernetes` | `IsolationRemote` | no |
| `remote` | `IsolationRemote` | no |

This is the isolation boundary working as intended. The hub does not forward its
own environment into an isolating executor, and a sandbox that could read the
hub's `~/.config` would not be a sandbox. These workloads get credentials the
same way as every other credential:
[through the secret broker](../guides/secrets.md#environment-secrets), as a
leased `env` grant scoped to a project or an executor and delivered for the life
of one workload:

```console
$ printf '{"ANTHROPIC_API_KEY":"sk-ant-…"}' | cloop secret mint claude-api --kind env
$ cloop secret grant claude-api --to project:/srv/app --env-keys ANTHROPIC_API_KEY --ttl 8h
```

The payload is a JSON object. If you pipe in `ANTHROPIC_API_KEY=sk-ant-…` as a
line instead, as an earlier version of this page showed, the broker stores it as
one bare value under the name `CLAUDE_API`. The grant above then delivers
nothing, and the run reaches `claude` logged out. The dashboard's
*Claude credential* dialog (below) builds the object for you.

### Checked before dispatch

Without this check, a sandbox with no credential would start anyway (a device
sometimes installing `claude` first) and fail its first task with
`auth_refused`, showing *Not logged in* in a transcript that said nothing about
grants. Expired grants failed the same way. Every path that dispatches a harness
to an isolating executor (`/api/run`, a project's Run, the new-project autorun,
the automatic resume after a usage cap, the Tasks tab's brainstorm and plan, the
assistant chat and a reproduction) runs one preflight
(`pkg/ui/harness_credential.go`) against the executor it resolved, before
anything is leased or started. The preflight computes the environment the run's
lease would carry: the same grants, matched the way a lease matches them (a
feature through its parent project), narrowed by each grant's `env_keys` and by
the project's `.cloop/sandbox.yaml` `env:` list. It refuses with a `409` when
that environment holds no credential the provider reads
(`harness_credential_missing`), or when the only grant that does ends within ten
minutes (`harness_credential_expiring`). The same applies when the lease itself
ends that soon, since a lease ends with the first of its grants to expire,
whatever its kind. The provider is judged the way the sandbox will choose it.
For a container, that is the project's own `config.yaml` and state, never the
hub's environment. For a device or a Pod, it is the provider its seeded state
carries (the hub's resolution for the project) or a `config.yaml` its
repository commits. Where the two could differ, a provider that needs no
credential wins, so a refusal is never based on a guess. The error names the
executor and the fix. `tests/arch` checks that every dispatch path builds the
preflight and that the dispatch primitives run it before they lease. Host
executors, providers other than `claudecode` and `anthropic`, and executors the
hub lists in `executors.harness_credential_exempt` (a device signed in as its
agent user, an image that brings a key) are not refused.

The project's Overview shows the result as a *Claude credential* card whenever
the executor isolates, and its dialog grants an existing `env` secret or a
pasted token in one step; see
[the Claude credential of a sandboxed run](../guides/secrets.md#the-claude-credential-of-a-sandboxed-run).
The API is `GET`/`POST /api/projects/{idx}/harness-credential`.

On an isolating executor, a *shared* credential is split per project or per
executor: every task placed there uses whatever the grant carries, whoever
pressed Run. A *personal* credential (an `env` secret that a signed-in user
owns, which is how the dialog stores a pasted token) is per user, like the
configuration directory on the hub. With OIDC on, the preflight counts it only
for runs its owner starts. Every other lease the hub issues (runs on any
executor, the host included, and workloads that run no harness at all) is told
to withhold it (`secretbroker.Requester.Withhold`), which records a
`secret.lease` denial naming the grant and the reason. Otherwise a token granted
to a shared project would bill its owner's subscription for every member's
runs, and a project holding two people's tokens would authenticate with
whichever one the lease rendered last. On the host it would also undo the
per-user directories: a leased token is appended after `ScopeHarnessEnv`'s
cleared assignment, and exec keeps the last occurrence of a key. An automatic
resume and a failover's replacement act for whoever started the run they
continue, as recorded in the hub's own database at dispatch, never in the
project's tree, which the sandbox can write (see
[resumed and failed-over runs](#resumed-and-failed-over-runs)). A static-token
or service-token run acts for no one, so only a shared credential satisfies it.
If a deployment needs per-user billing end to end, each user grants their own
credential. If it needs a team account, a maintainer grants a shared one.

Note the direction of `IsolatesFromHost`: a driver that declares no isolation
level is treated as not isolated, so it does receive the directory. A workload
that runs on the hub can read the path, and one that does not is refused
separately by [strict no-host-execution](model.md#the-no-host-execution-guarantee),
instead of being credited with isolation it never claimed.

### Behind the model relay the credential stays on the hub

A grant delivers the credential *into* the sandbox, where the workload holds
the plaintext for the whole run. With
[`executors.model_relay`](../reference/configuration.md#the-model-relay-for-sandboxed-runs)
on (it is off by default), it does not. The dispatch still runs the preflight
above and still leases the grant, because that decides whether the run may
start and whose credential it spends, Withhold included. But it takes the Claude
credential back out of the environment it built and mints a relay session on
the run's lease instead. The sandbox gets `ANTHROPIC_BASE_URL` pointing at the
hub and a session token, and the hub spends the credential against the API. As
a result:

- **The workload never holds it.** It is not in its environment, its files or
  its harness's `/proc/<pid>/environ`
  (`TestARelayedRunNeverHoldsItsClaudeCredential`). A session token that is
  printed or committed is good only for the run's model calls, and only until
  the run ends.
- **A revocation reaches the running task.** Revoking the grant or the lease
  ends the session, and the task's next model call is refused with the reason.
  A delivered variable could never be taken back like this
  (`TestModelRelaySessionEndsWithItsGrantAndItsLease`).
- **Spend is measured, not self-reported.** Each response's usage is counted
  from the API's own answer and charged to the identity that started the run. A
  call past its `daily_token_budget` or `daily_cost_usd` is refused before it
  reaches the API (`TestModelRelayRefusesPastThePayersBudget`).
- **The hub decides which models are allowed.** The hub's allowlist, which a
  project can narrow but never widen, decides which models a run may call.

The relay carries only credential kinds that have been tested end to end through
it against the real API. A Claude OAuth token has been. An Anthropic API key has
not yet, so a project granted one keeps the current delivery, and its card says
*not relayed* (`TestModelRelayLeavesAnUnprovenCredentialAsBefore`). The hub's
own `anthropic.api_key` is never spent for a run unless an administrator lists
the project or executor in `executors.model_relay.hub_credential`. See
[the Claude credential of a sandboxed run](../guides/secrets.md#with-the-model-relay-on-the-claude-credential-stays-on-the-hub)
for what a run shows.

---

## Resumed and failed-over runs

Three kinds of dispatch happen without anyone asking: the
[automatic resume](../reference/configuration.md#resuming-a-capped-run) after a
usage cap (which also follows every exhausted five-hour window that held a run
out of extra usage), the same resume when a leader hands it to another cluster
member, and a
[failover](../architecture/executors.md#the-replacement-is-the-projects-run-task-20396)'s
replacement. Older builds gave the dispatcher no account for these, so on a hub
with single sign-on a resumed run on the hub's own host inherited the
`cloop ui` process's environment. On a live hub whose service ran with
`HOME=/root` and no `CLAUDE_CONFIG_DIR`, the run a person started carried their
directory and its own token, and the run the hub resumed carried neither. It ran
on the shared login this page is about removing, on somebody else's
subscription, or failed as not logged in.

Each of them now acts for the person who started the run it continues
(`pkg/ui/resume_account.go`):

| | |
| --- | --- |
| **Whom** | the identity the control plane recorded when that run was dispatched (`harness.initiator.run:<project>` in the hub's own database, never the project's tree, which the sandbox can write), or, for a run older than that record, the project's owner. The record names the run it was written for. A paused run that recorded itself (`run_owner`) well after that dispatch, such as a `cloop run` started from a shell, even one that took the hub's run id from the placement record, is not carried on as whoever last pressed Run here. `run_owner` is in the project's tree, which the run can write, so this check stops the hub misattributing a run. It is not a boundary against a workload on the hub's own host, which can read every home there |
| **Which account** | chosen the same way as for a request (`claudeEnvFor`). On an executor that shares the hub's filesystem, it is that person's directory, with the ambient token cleared. On an isolating executor there is no directory: the lease delivers the project's grants as before, and a personal grant counts for that person |
| **Which usage** | an extra-usage pause recorded by an older build clears according to that person's own usage windows, read under their directory, never the hub's own login's |
| **The trail** | `run.cap_resumed` carries `acted_for` and `acted_for_basis` (`starter`, `owner` or `unknown`). A failover's `executor.failover` row carries `acted_for`, and its Event History row says whom the replacement acts for. A resume records only the basis it acted on: an owner fallback stays `owner`, and a run nobody could be named for stays `unknown` |

A resume never creates a directory. A directory is made when its owner signs in
or starts something, and a machine acting for them later either finds it or
does not. The dispatch is refused in the following cases, decided with the rest
of the [preflight](#checked-before-dispatch) against the executor the dispatch
resolved, before anything is leased:

- Their directory is gone (offboarding removed it, or they never signed in
  here) and the run would share the hub's filesystem, where it would use that
  directory.
- The hub denies them (a deny binding on them, hub-wide or on this project, or a
  deactivation at the identity provider). This applies on any executor, because
  an isolating run would still spend their personal grants.
- The executor is restricted to an access list that provably does not admit
  them: every entry names a person by the key the hub knows them by (their
  email, or their subject when the identity provider released no email), and
  none of them is the starter. Their own Run would get a 403 there. A group or
  role entry, or a subject entry for someone known by email, may admit them
  through a claim of their sign-in, which a resume does not have, so such a list
  is left to admit them as it did when they started the run.
- Nobody can be named (no record and a project with no owner, a record of a
  different run than the one paused, or the hub's two records disagreeing
  because an older hub build dispatched since), and the run would be on the
  hub's filesystem, where the alternative is the hub's own login.
- An extra-usage pause recorded by an older build has no usage to be judged by,
  because there is nobody's directory to read it under.
- The control plane cannot be read. In this case the dispatch is refused but the
  run is not held: the next sweep asks again.

The run then waits, paused as *starter's Claude account unavailable*
(`starter_unavailable`) and naming the person, and the project's Event History
says why. It is not resumed on a timer. Whoever presses Run starts it as
themselves, on their own account. The project's readers see the same reason for
a directory that is gone and for a person the hub denies (*has no Claude Code
login on this hub that the hub may use for them*), because whether and why the
hub denies someone (an offboarding's reason, a legal hold, a suspension at the
identity provider) is for its operators, and goes only to the hub's log. If a
dispatch ever paired such an account with a clearance that does not check it,
its pin would still name no login: `CLAUDE_CONFIG_DIR` points under `/dev/null`,
where nobody can create it, and the ambient token is cleared.

A run started by a caller that acts for no one ([below](#callers-with-no-identity))
ran on the hub's own login, and so does its resume. A hub without single
sign-on has one operator and one login, which every run, resumed or not, uses as
before.

`tests/arch` enforces this (`TestEveryDispatchPinsAClaudeAccount`): no
production dispatch passes a nil environment resolver except listed ones that
run no model, and a dispatch acting for a recorded starter pins that same
account. The behaviour is tested by `TestAutoResumeActsOnTheStartersClaudeAccount`
(a stub `claude` sees each starter's directory and no ambient token),
`TestLegacyPauseClearsByTheStartersUsage`, `TestAnOffboardedStartersRunStaysPaused`,
`TestALegacyPauseOfAnOffboardedStarterIsHeld`,
`TestARunStartedOutsideTheHubIsNotCarriedOnAsTheLastStarter`,
`TestAResumeRecordsTheBasisItActedOn`, `TestARecordAnOlderBuildOverwroteIsNotTrusted`,
`TestProjectDeniesAndExecutorAccessListsRefuseTheResume`,
`TestATransientControlPlaneErrorDoesNotHoldTheRun`,
`TestFailoverOntoAHostSharingExecutorCarriesTheStartersHome` and
`TestFailoverForAStarterWithNoHomeStaysPaused`.

Two known gaps remain. A build too old to record its own run cannot be told
apart from the run the record describes, so a run that such a build started
from a shell, in a project the hub also runs, is carried on as the hub's last
starter. A hub keeps a run's build for as long as the run lives, and the next
run starts on the hub's build. A run started from a shell within a minute of the
hub's dispatch cannot be told apart from it either. And a resume checks the
person again against the hub's deny list and the executor's user entries, but
not against everything that let them start the run. Their groups and roles are
claims of a sign-in, which a machine acting for them does not have, so a person
removed from a project's members, or from the group that a role mapping or an
access list names, is still acted for until a deny binding names them.
Offboarding writes one.

---

## Callers with no identity

With OIDC on, `claudeScopeFor` fails closed. When the hub cannot tell who the
caller is, it must not fall back to the shared account, so the auth and usage
endpoints answer `403` for these callers:

- the static bearer token (`--token` / `CLOOP_UI_TOKEN`), which carries no
  owner binding,
- a scoped API token from `cloop hub token create`, which is minted with roles
  but not on a user's behalf.

Delegated links do resolve. A display-glasses token is bound to its owner when
it is minted, so it reads that owner's Claude status and usage, like everything
else it does.

Run dispatch is the exception. `claudeWorkloadEnv` returns nothing when the
scope cannot be resolved, so a run started by one of these callers uses the
host credential instead of failing. The endpoints fail closed but the dispatch
falls back, because refusing would break non-interactive automation on every
hub that has any. It does mean that an unattended caller's runs are not
attributed to any user. If that matters, give automation its own project on an
isolating executor with its own grant, or don't leave a host credential for it
to fall back to. Runs started outside HTTP entirely (`cloop run` on the hub, a
scheduled job) are in the same position for the same reason. A run that one of
these callers started is also resumed after a usage cap, or failed over, on the
host credential, since that is the account it started on. A run that a person
started never is (see
[resumed and failed-over runs](#resumed-and-failed-over-runs)).

---

## Deprovisioning a user

Removing someone from the IdP group stops them signing in. It does not touch
the refresh token in their directory, and `claude auth logout` revokes the
session but leaves the directory in place. As long as a former employee's
rotating refresh token is on the hub's disk, they have not been fully removed.

Offboarding removes it. `cloop hub user offboard` and **Secrets → Offboard a
user** end the person's Claude Code login on every hub member, under every
spelling of their identity (their email, and `sub:<subject>` from any time the
IdP withheld the email):

1. A `claude auth login` they had in progress is cancelled on the member
   holding it, and that member gives up its claim on it.
2. Each home with a credential is logged out with `claude auth logout`, scoped
   to that directory alone, which revokes the session at Anthropic and not only
   on disk. This is best-effort: a failure is reported and the directory is
   removed anyway. A hub with `executors.allow_host_process: false` skips this
   step, because it runs no program on a request's behalf, and says so. The
   CLI, run from an operator's shell, does it for the tree beside it whatever
   the policy. A home that is a symbolic link is never logged out through,
   because that would sign out whatever the link points at; it is removed
   without being followed.
3. The directory is removed with `claudecodeauth.ForgetHome`, credential and
   transcripts together. The person's tasks were told to stop just before, so
   no run of theirs is still writing there.

A home lives under the config directory of the process that created it, so a
cluster whose members run under different users or container filesystems has
one per member. The member serving a dashboard offboarding asks the others over
the peer channel, and the CLI asks them over the bus. A member that cannot be
asked is reported, never assumed empty; see
[offboarding in the security model](model.md#offboarding-what-a-departed-identity-keeps).
Under a legal hold (`--keep-credentials`), the login in progress is still
cancelled and the homes are kept as they are. The offboarding records the hold
on the identity first, so nothing removes them later until the hold is
released.

Copies the offboarding could not reach are removed later. When it starts, and
hourly after that, every hub member removes from its own tree the home of every
identity the control plane denies hub-wide, using the same three steps, and
records each removal as `user.claude_home_swept`. It leaves alone an identity
under a legal hold, and one denied only by a SCIM suspension that is still in
force, which a reactivation undoes. A stopped member's tree is cleaned up when
that member starts again. `cloop hub doctor` fails `offboard.claude_homes`
while such a home is still on its host, and names each directory.

To do it by hand on a host where no member will run again, compute the slug and
remove the directory:

```console
$ slug=$(printf '%s' 'dana@example.com' | sha256sum | cut -c1-32)
$ rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/cloop/claude-identities/$slug"
```

Removing a directory is safe while the hub is running. A request from that
identity would create an empty one again, and the user would be logged out.
After an offboarding no such request comes, because the identity is denied.

A run of theirs waiting at a usage cap is not resumed afterwards, on the hub's
login or anyone else's. It stays paused as *starter's Claude account
unavailable* until a colleague starts it as themselves.

---

## What this does not do

- **It does not revoke anything upstream.** Deleting a directory destroys the
  hub's copy of a credential. The Claude account itself is unaffected; only the
  user (or Anthropic) can revoke the OAuth grant.
- **It does not separate quota.** Each user spends their own subscription, but
  cloop enforces no limit across users. Use
  [quotas](model.md#quotas-how-much-not-whether) for hub-side limits. A run
  behind the [model relay](#behind-the-model-relay-the-credential-stays-on-the-hub)
  is held to them call by call, based on what the API counted.
- **It does not reach isolating executors** with a directory, as described
  above. There, a user's own Claude login is a personal `env` grant, spent only
  on their runs. Behind the model relay, the hub spends it on their behalf
  instead of handing it to the sandbox.
- **It does not protect against a hostile host.** Every identity's directory
  lives under one uid on one filesystem. `0700` stops other *users* of that
  machine, but not anything that already runs as the hub, which includes any
  agent executed on `localprocess`. That is one more reason to use
  [`executors.allow_host_process: false`](model.md#the-no-host-execution-guarantee),
  and per-user logins do not change that recommendation.

---

See also: [security model](model.md), [threat model](threat-model.md),
[providers](../getting-started/providers.md), and
[granting secrets](../guides/secrets.md).
